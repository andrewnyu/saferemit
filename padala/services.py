"""Wiring: one object that owns the database, keys, gateway, PayPal and the agent.

Also holds the small amount of application logic that is neither crypto nor
verification: device-key registration, PayPal vault onboarding, plan drafts and
activation, and the budget summaries the dashboards show.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import date, timedelta
from pathlib import Path
from typing import Callable

import httpx

from padala import keys
from padala.agent import BillAgent, today_manila
from padala.config import Settings
from padala.crypto import jws, sdjwt
from padala.crypto.jwk import load_public_jwk, public_jwk, thumbprint
from padala.db import Database, now
from padala.gateway import Gateway
from padala.mandates import model as m
from padala.mandates import open_mandate
from padala.paypal import make_client
from padala.paypal.client import PayPalError
from padala.paypal.fx import FxProvider
from padala.paypal.settlement import PayPalSettler

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
PAYOUT_POLL_SECONDS = 3
PAYOUT_FAILED = {"FAILED", "RETURNED", "BLOCKED", "REVERSED", "REFUNDED", "DENIED", "CANCELED"}


class Services:
    def __init__(self, settings: Settings, paypal_client=None, clock: Callable[[], float] = time.time):
        self.settings = settings
        self.clock = clock
        self.db = Database(settings.db_path)
        self.agent_key = keys.load_or_create(settings.keys_dir / "agent.pem")
        self.gateway_key = keys.load_or_create(settings.keys_dir / "gateway.pem")
        self.paypal = paypal_client or make_client(settings)
        self.fx = FxProvider(self.db, offline=settings.fx_offline, fallback_rate=settings.fx_fallback_rate)
        self.gateway = Gateway(self.db, self.gateway_key,
                               PayPalSettler(self.paypal, self.fx, self.vault_id),
                               audience=settings.gateway_audience, clock=clock)
        self.agent = BillAgent(self)
        self._payout_checked: dict[int, float] = {}

    @property
    def agent_jwk(self) -> dict:
        return public_jwk(self.agent_key)

    # ------------------------------------------------------------------ device keys

    def register_device_key(self, jwk: dict, label: str = "OFW browser") -> str:
        load_public_jwk(jwk)  # validates P-256, rejects private keys
        clean = {k: jwk[k] for k in ("kty", "crv", "x", "y")}
        kid = thumbprint(clean)
        self.db.run("INSERT OR IGNORE INTO device_keys (kid, jwk, label, created_at) VALUES (?,?,?,?)",
                    kid, json.dumps(clean), label, now())
        return kid

    def device_key(self) -> dict | None:
        row = self.db.one("SELECT * FROM device_keys WHERE revoked = 0 ORDER BY created_at DESC LIMIT 1")
        return dict(row) if row else None

    # ------------------------------------------------------------------ PayPal vault onboarding

    def start_vault(self) -> str:
        request_id = str(uuid.uuid4())
        base = self.settings.base_url
        token = self.paypal.create_setup_token(return_url=f"{base}/ofw/vault/return",
                                               cancel_url=f"{base}/ofw/onboarding?vault=cancelled",
                                               request_id=request_id)
        self.db.run("INSERT INTO vault (mode, status, setup_token_id, created_at) VALUES (?,?,?,?)",
                    self.paypal.mode, "pending_approval", token["id"], now())
        return token["approve_url"]

    def complete_vault(self, setup_token_id: str | None = None) -> dict:
        row = self.db.one("SELECT * FROM vault WHERE status = 'pending_approval' "
                          + ("AND setup_token_id = ? " if setup_token_id else "")
                          + "ORDER BY id DESC LIMIT 1", *([setup_token_id] if setup_token_id else []))
        if row is None:
            raise ValueError("no vault setup in progress")
        token = self.paypal.create_payment_token(setup_token_id=row["setup_token_id"],
                                                 request_id=f"padala-pt-{row['setup_token_id']}")
        self.db.run("UPDATE vault SET status = 'active', vault_id = ?, customer_id = ?, payer_email = ? WHERE id = ?",
                    token["vault_id"], token["customer_id"], token["payer_email"], row["id"])
        return token

    def vault(self) -> dict | None:
        row = self.db.one("SELECT * FROM vault WHERE status = 'active' ORDER BY id DESC LIMIT 1")
        return dict(row) if row else None

    def vault_id(self) -> str | None:
        v = self.vault()
        return v["vault_id"] if v else None

    # ------------------------------------------------------------------ plans (open mandates)

    def payees(self) -> list[dict]:
        out = []
        for row in self.db.all("SELECT * FROM payees ORDER BY category, name"):
            d = dict(row)
            d["aliases"] = json.loads(d["aliases"])
            out.append(d)
        return out

    def default_plan(self) -> m.Plan:
        today = date.fromisoformat(today_manila(self.clock()))
        first = today.replace(day=1)
        payees = [m.Payee(p["id"], p["name"], p["category"], p["account_number"], p["paypal_email"], p.get("website"))
                  for p in self.payees()]
        return m.Plan(
            payees=payees, monthly_budget_minor=40_000_00, max_payments_per_month=12,
            amount_min_minor=100_00, amount_max_minor=30_000_00,
            caps=[m.CategoryCap("education", 15_000_00, "WINDOW", first.isoformat(),
                                (first + timedelta(days=150)).isoformat(), "per term"),
                  m.CategoryCap("utilities", 6_000_00), m.CategoryCap("medical", 10_000_00),
                  m.CategoryCap("housing", 18_000_00)],
            step_up_over_minor=15_000_00, not_before=today.isoformat(),
            not_after=(today + timedelta(days=30)).isoformat(), valid_days=30,
            ofw_name="Ate Liza (California)", household="Santos family, Bacolod")

    def create_draft(self, plan: m.Plan, kid: str | None = None) -> tuple[int, open_mandate.Draft]:
        """Prepare the open mandate for the browser holding device key `kid` to sign."""
        key = (self.db.one("SELECT * FROM device_keys WHERE kid = ? AND revoked = 0", kid) if kid
               else self.device_key())
        if key is None:
            raise ValueError("register a device key first")
        draft = open_mandate.prepare(plan, self.agent_jwk, key["kid"], int(self.clock()))
        plan_id = self.db.run("INSERT INTO plans (status, settings, draft, kid, created_at) VALUES (?,?,?,?,?)",
                              "draft", json.dumps(plan.to_dict()), json.dumps(draft.to_dict()), key["kid"], now())
        return plan_id, draft

    def activate_plan(self, plan_id: int, signature_b64url: str) -> str:
        """Attach the browser's signature and verify it before trusting it."""
        row = self.db.one("SELECT * FROM plans WHERE id = ? AND status = 'draft'", plan_id)
        if row is None:
            raise ValueError("no such draft plan")
        d = json.loads(row["draft"])
        draft = open_mandate.Draft(d["header"], d["payload"], d["disclosures"])
        token = open_mandate.finalize(draft, signature_b64url)
        key = self.db.one("SELECT jwk FROM device_keys WHERE kid = ?", row["kid"])
        verified = sdjwt.verify(token, load_public_jwk(json.loads(key["jwk"])), expected_typ=m.ISSUER_TYP)
        content = verified.claims["delegate_payload"][0]
        mid = open_mandate.mandate_id(token)
        with self.db.transaction() as conn:
            conn.execute("UPDATE plans SET status = 'superseded' WHERE status = 'active'")
            conn.execute("UPDATE plans SET status = 'active', sd_jwt = ?, mandate_id = ?, signed_at = ?, exp = ? "
                         "WHERE id = ?", (token.serialize(), mid, now(), content["exp"], plan_id))
        return mid

    def active_plan(self) -> dict | None:
        row = self.db.one("SELECT * FROM plans WHERE status = 'active' ORDER BY id DESC LIMIT 1")
        return dict(row) if row else None

    def active_plan_model(self) -> m.Plan | None:
        plan = self.active_plan()
        return m.Plan.from_dict(json.loads(plan["settings"])) if plan else None

    # ------------------------------------------------------------------ dashboards

    def budget_summary(self) -> dict | None:
        plan_row, plan = self.active_plan(), self.active_plan_model()
        if plan is None:
            return None
        today = today_manila(self.clock())
        ledger = self.gateway.ledger
        mid = plan_row["mandate_id"]
        spent = ledger.spent(mid, today[:7])
        categories = []
        for cap in plan.caps:
            window = f"W:{cap.not_before}..{cap.not_after}" if cap.period == "WINDOW" else f"M:{today[:7]}"
            used = ledger.category_spent(mid, cap.category, window)
            categories.append({"category": cap.category, "max": cap.max_minor, "spent": used,
                               "left": max(cap.max_minor - used, 0), "label": cap.label or "this month",
                               "pct": min(100, round(100 * used / cap.max_minor)) if cap.max_minor else 0})
        return {"month": today[:7], "budget": plan.monthly_budget_minor, "spent": spent,
                "left": max(plan.monthly_budget_minor - spent, 0),
                "pct": min(100, round(100 * spent / plan.monthly_budget_minor)), "categories": categories,
                "exp": plan_row["exp"], "step_up_over": plan.step_up_over_minor}

    # ------------------------------------------------------------------ payouts after the charge

    def reconcile_payouts(self, bill_id: int | None = None) -> None:
        """PayPal accepts a payout as PENDING and delivers it later, so a bill only
        becomes `paid` once the payout item reports SUCCESS. A payout that ends badly
        refunds the OFW and returns the budget. With no bill_id this runs on page
        views, at most once per PAYOUT_POLL_SECONDS for each payment."""
        query = ("SELECT p.id, p.bill_id, p.capture_id, p.payout_batch_id, b.transaction_id FROM payments p "
                 "JOIN bills b ON b.id = p.bill_id WHERE p.status = 'paying'")
        rows = self.db.all(query + " AND p.bill_id = ?", bill_id) if bill_id else self.db.all(query)
        for row in rows:
            if bill_id is None and self.clock() - self._payout_checked.get(row["id"], 0) < PAYOUT_POLL_SECONDS:
                continue
            self._payout_checked[row["id"]] = self.clock()
            try:
                state = self.paypal.get_payout(row["payout_batch_id"])
            except (PayPalError, httpx.HTTPError):
                continue  # still processing as far as we know; the next view tries again
            status = state.get("item_status") or state.get("batch_status")
            self.db.run("UPDATE payments SET payout_status = ? WHERE id = ?", status, row["id"])
            if status == "SUCCESS":
                outcome, bill_status = "paid", "paid"
            elif status in PAYOUT_FAILED:
                outcome, bill_status = "payout_failed", "failed"
            else:
                continue  # PENDING, PROCESSING, UNCLAIMED, ONHOLD: not finished
            with self.db.connect() as conn:  # only one request gets to act on this result
                won = conn.execute("UPDATE payments SET status = ? WHERE id = ? AND status = 'paying'",
                                   (outcome, row["id"])).rowcount == 1
            if not won:
                continue
            detail = None
            if outcome == "payout_failed":
                note = self.gateway.reverse_failed_payout(row["transaction_id"], row["capture_id"])
                reason = f": {state['error']}" if state.get("error") else ""
                detail = f"PayPal could not deliver the payout ({status}{reason}); {note}"
                self.db.run("UPDATE payments SET error = ? WHERE id = ?", detail, row["id"])
            self.db.run("UPDATE bills SET status = ?, status_detail = ?, updated_at = ? WHERE id = ?",
                        bill_status, detail, now(), row["bill_id"])

    def reset_demo(self) -> None:
        """Wipe demo state (bills, plans, ledger, keys registered by browsers) and reseed."""
        with self.db.transaction() as conn:
            for table in ("approvals", "payments", "bills", "plans", "vault", "device_keys", "gw_nonces",
                          "gw_ledger", "gw_receipts", "gw_evidence", "bill_history", "payees", "kv"):
                conn.execute(f"DELETE FROM {table}")
        seed_registry(self)

    def receipt(self, receipt_id: str) -> dict | None:
        row = self.db.one("SELECT * FROM gw_receipts WHERE id = ?", receipt_id)
        if row is None:
            return None
        d = dict(row)
        d["trace"] = json.loads(d["trace"])
        decoded = jws.decode_unverified(d["receipt_jwt"])
        d["header"], d["payload"] = decoded.header, decoded.payload
        return d


def seed_registry(services: Services, data: dict | None = None) -> None:
    """Load payees and bill history (samples/payees.json), honouring
    PAYEE_EMAIL_* overrides so sandbox payouts go to your own business accounts."""
    import os

    data = data or json.loads((SAMPLES / "payees.json").read_text())
    for p in data["payees"]:
        email = os.environ.get(f"PAYEE_EMAIL_{p['env']}", p["paypal_email"])
        services.db.run("INSERT INTO payees (id, name, category, account_number, paypal_email, website, aliases) "
                        "VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, "
                        "category=excluded.category, account_number=excluded.account_number, "
                        "paypal_email=excluded.paypal_email, website=excluded.website, aliases=excluded.aliases",
                        p["id"], p["name"], p["category"], p["account_number"], email, p.get("website"),
                        json.dumps(p.get("aliases", [])))
        for period, amount in p.get("history", {}).items():
            services.db.run("INSERT OR REPLACE INTO bill_history (payee_id, period, amount_minor) VALUES (?,?,?)",
                            p["id"], period, amount)
