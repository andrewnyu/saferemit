"""The bill agent: turns a family-submitted bill into a closed Payment Mandate.

Pipeline for one bill:

    image -> store as evidence (sha-256, perceptual hash)
          -> Claude extraction (or a labelled offline fixture)
          -> deterministic checks (registry, account, line items, seasonal anomaly, duplicate)
          -> agent-signed evidence JWT  (transaction_id = its hash)
          -> closed mandate signed with the agent key, minimal disclosures
          -> gateway (deterministic) -> paid | rejected | step-up to the OFW

The agent never decides whether money moves. Even a bill it has flagged is
presented, so the gateway issues a signed rejection receipt that the OFW can
see; the agent cannot talk the gateway into anything the OFW did not sign.
"""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from padala.crypto import jws, sdjwt
from padala.crypto.jwk import load_public_jwk
from padala.db import now
from padala.evidence import dhash, sha256_hex, to_minor
from padala.gateway import GatewayResult, Presentation
from padala.gateway.verifier import STEP_UP_TYP
from padala.intake.checks import run_checks
from padala.intake.extract import IntakeError, extract_bill, extract_offline
from padala.mandates import closed_mandate as cm
from padala.mandates import model as m

if TYPE_CHECKING:
    from padala.services import Services

MANILA = timezone(timedelta(hours=8))
_EXT = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}


def today_manila(clock_seconds: float) -> str:
    return datetime.fromtimestamp(clock_seconds, MANILA).date().isoformat()


class BillAgent:
    def __init__(self, services: "Services"):
        self.s = services
        self._present_lock = threading.Lock()  # one presentation per open mandate at a time (AP2)

    # ------------------------------------------------------------------ intake

    def submit_bill(self, image_bytes: bytes, *, filename: str, mime: str, submitted_by: str) -> int:
        db, settings = self.s.db, self.s.settings
        image_sha = sha256_hex(image_bytes)
        phash = dhash(image_bytes)
        path = Path(settings.uploads_dir) / f"{image_sha}.{_EXT.get(mime, 'img')}"
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(image_bytes)
        self.s.gateway.register_evidence(image_sha, str(path), mime, phash)

        prior = [dict(r) for r in db.all("SELECT id, phash FROM bills WHERE status IN ('paid', 'paying', 'awaiting_ofw')")]
        bill_id = db.run(
            "INSERT INTO bills (submitted_by, filename, mime, image_sha256, phash, status, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?)", submitted_by, filename, mime, image_sha, phash, "extracting", now(), now())

        try:
            if settings.use_claude:
                result = extract_bill(image_bytes, settings)
            else:
                result = extract_offline(image_sha)
        except IntakeError as exc:
            self._set(bill_id, "needs_review", str(exc))
            self._escalate(bill_id, "intake", str(exc))
            return bill_id

        extraction = result.extraction.model_dump()
        period = self._period(extraction)
        payees = [self._payee_row(r) for r in db.all("SELECT * FROM payees")]
        matched, checks, anomaly = run_checks(
            extraction, payees=payees, history=self._history(extraction, payees), period=period,
            phash=phash, prior_bills=prior)
        db.run("UPDATE bills SET extraction = ?, extraction_source = ?, checks = ?, status_detail = ?, "
               "updated_at = ? WHERE id = ?", json.dumps(extraction), result.label,
               json.dumps({"checks": [c.to_dict() for c in checks], "anomaly": anomaly,
                           "matched_payee": matched["id"] if matched else None}), None, now(), bill_id)

        plan = self.s.active_plan()
        if plan is None:
            self._set(bill_id, "waiting_for_plan", "no signed remittance plan yet")
            return bill_id

        evidence = cm.evidence_jwt(self.s.agent_key, image_sha256=image_sha, phash=phash, extraction=extraction,
                                   extraction_source=result.source, iat=now())
        open_token = sdjwt.parse(plan["sd_jwt"])
        payee = self._payee_for_mandate(open_token, matched, extraction)
        content = cm.closed_mandate_content(
            transaction_id=cm.transaction_id_for(evidence), payee=payee,
            amount_minor=to_minor(extraction["amount_due"]), currency=extraction["currency"],
            execution_date=today_manila(self.s.clock()))
        db.run("UPDATE bills SET evidence_jwt = ?, transaction_id = ?, closed_content = ?, updated_at = ? "
               "WHERE id = ?", evidence, content["transaction_id"], json.dumps(content), now(), bill_id)
        self._present(bill_id, open_token, content, evidence)
        return bill_id

    # ------------------------------------------------------------------ OFW decisions

    def approve_step_up(self, approval_id: int, decision_jws: str) -> GatewayResult:
        """Re-present the same closed mandate, now with the OFW's signature."""
        approval = self.s.db.one("SELECT * FROM approvals WHERE id = ? AND status = 'pending'", approval_id)
        if approval is None or approval["kind"] != "step_up":
            raise ValueError("no pending step-up approval with that id")
        bill = self.s.db.one("SELECT * FROM bills WHERE id = ?", approval["bill_id"])
        plan = self.s.active_plan()
        if plan is None:
            raise ValueError("no active plan")
        decision = jws.decode_unverified(decision_jws).payload.get("decision")
        result = self._present(bill["id"], sdjwt.parse(plan["sd_jwt"]), json.loads(bill["closed_content"]),
                               bill["evidence_jwt"], step_up_decision=decision_jws, from_approval=True)
        status = "approved" if decision == "approve" else "declined"
        self.s.db.run("UPDATE approvals SET status = ?, decision_jws = ?, decided_at = ? WHERE id = ?",
                      status, decision_jws, now(), approval_id)
        return result

    def decline_escalation(self, approval_id: int, decision_jws: str) -> None:
        """The OFW declines a bill the gateway already rejected (signed, for the record)."""
        approval = self.s.db.one("SELECT * FROM approvals WHERE id = ? AND status = 'pending'", approval_id)
        if approval is None:
            raise ValueError("no pending escalation with that id")
        decoded = jws.decode_unverified(decision_jws)
        row = self.s.db.one("SELECT jwk FROM device_keys WHERE kid = ? AND revoked = 0", decoded.header.get("kid"))
        if row is None:
            raise ValueError("decision not signed by a registered device key")
        payload = jws.verify(decision_jws, load_public_jwk(json.loads(row["jwk"])), expected_typ=STEP_UP_TYP).payload
        if payload.get("decision") != "decline" or payload.get("bill_id") != approval["bill_id"]:
            raise ValueError("decision does not decline this bill")
        self.s.db.run("UPDATE approvals SET status = 'declined', decision_jws = ?, decided_at = ? WHERE id = ?",
                      decision_jws, now(), approval_id)
        self._set(approval["bill_id"], "declined", "declined by the OFW")

    # ------------------------------------------------------------------ internals

    def _present(self, bill_id: int, open_token: sdjwt.SdJwt, content: dict, evidence: str,
                 step_up_decision: str | None = None, from_approval: bool = False) -> GatewayResult:
        gateway = self.s.gateway
        mandate = self.s.active_plan()["mandate_id"]
        with self._present_lock:
            presentation = cm.build_presentation(
                open_token=open_token, agent_key=self.s.agent_key, content=content,
                aud=gateway.audience, nonce=gateway.issue_nonce(), iat=int(self.s.clock()),
                prev_receipt=gateway.latest_receipt(mandate))
            result = gateway.process(Presentation(presentation.chain, evidence, step_up_decision), bill_id=bill_id)

        db = self.s.db
        db.run("UPDATE bills SET receipt_id = ?, updated_at = ? WHERE id = ?", result.receipt_id, now(), bill_id)
        if result.outcome == "paid":
            st = result.settlement
            db.run("INSERT INTO payments (bill_id, receipt_id, php_minor, usd_cents, fx_rate, fx_source, order_id, "
                   "capture_id, payout_batch_id, payout_status, paypal_mode, status, created_at) "
                   "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", bill_id, result.receipt_id,
                   content["payment_amount"]["amount"], st.usd_cents, st.fx_rate, st.fx_source, st.order_id,
                   st.capture_id, st.payout_batch_id, st.payout_status, st.mode, "paying", now())
            self._set(bill_id, "paying", None)
            self.s.reconcile_payouts(bill_id)
        elif result.outcome == "step_up_required":
            self._set(bill_id, "awaiting_ofw", result.error_description)
            if not from_approval:
                self._escalate(bill_id, "step_up", result.error_description, payload=content)
        elif result.outcome == "settlement_failed":
            self._set(bill_id, "failed", result.error_description)
        else:
            declined = result.error == "declined_by_ofw"
            self._set(bill_id, "declined" if declined else "rejected", result.error_description)
            if not declined and not from_approval:
                self._escalate(bill_id, "escalation", f"{result.error}: {result.error_description}")
        return result

    def _set(self, bill_id: int, status: str, detail: str | None) -> None:
        self.s.db.run("UPDATE bills SET status = ?, status_detail = ?, updated_at = ? WHERE id = ?",
                      status, detail, now(), bill_id)

    def _escalate(self, bill_id: int, kind: str, reason: str | None, payload: dict | None = None) -> None:
        self.s.db.run("INSERT INTO approvals (bill_id, kind, status, reason, payload, created_at) "
                      "VALUES (?,?,?,?,?,?)", bill_id, kind, "pending", reason,
                      json.dumps(payload) if payload else None, now())

    def _payee_for_mandate(self, open_token: sdjwt.SdJwt, matched: dict | None, extraction: dict) -> dict:
        """Use the exact Merchant object the OFW signed. If the biller is not in
        the mandate, describe it from the bill; the gateway will refuse it."""
        if matched:
            for d in open_token.decoded_disclosures():
                if isinstance(d.value, dict) and d.value.get("id") == matched["id"] and "paypal_email" in d.value:
                    return d.value
            # A known payee the OFW did not put in this plan.
            return m.Payee(matched["id"], matched["name"], matched["category"], matched["account_number"],
                           matched["paypal_email"], matched.get("website")).as_merchant()
        slug = re.sub(r"[^a-z0-9]+", "-", extraction["biller_name"].lower()).strip("-")[:40]
        return {"id": f"unregistered:{slug}", "name": extraction["biller_name"], "category": extraction["category"],
                "account_number": extraction.get("account_number") or "", "paypal_email": ""}

    def _history(self, extraction: dict, payees: list[dict]) -> dict[str, int]:
        from padala.intake.checks import match_payee

        payee = match_payee(extraction["biller_name"], payees)
        if not payee:
            return {}
        rows = self.s.db.all("SELECT period, amount_minor FROM bill_history WHERE payee_id = ?", payee["id"])
        return {r["period"]: r["amount_minor"] for r in rows}

    def _period(self, extraction: dict) -> str:
        due = extraction.get("due_date")
        if due and re.match(r"^\d{4}-\d{2}", due):
            # Bills are due the month after the usage period.
            year, month = int(due[:4]), int(due[5:7])
            year, month = (year, month - 1) if month > 1 else (year - 1, 12)
            return f"{year:04d}-{month:02d}"
        return today_manila(self.s.clock())[:7]

    @staticmethod
    def _payee_row(row) -> dict:
        d = dict(row)
        d["aliases"] = json.loads(d.get("aliases") or "[]")
        return d
