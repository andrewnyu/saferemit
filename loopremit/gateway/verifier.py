"""The Loop Remit gateway: deterministic verification of the AP2 mandate chain.

No LLM is involved anywhere in this file. Given a presentation from the bill
agent, the gateway:

  1. parses the `~~`-joined chain (open mandate SD-JWT, closed mandate hop),
  2. verifies the open mandate against the OFW's *registered device key*,
  3. resolves the open mandate's disclosures against its signed digests,
  4. checks the open mandate type and lifetime (`vct`, `iat`, `exp`),
  5. verifies the closed hop with the agent key in `cnf` and its key binding
     (`aud`, single-use `nonce`, `iat`, `sd_hash`),
  6. resolves the closed mandate content,
  7. enforces AP2's one-presentation-at-a-time rule via the receipt chain,
  8. evaluates every constraint (unknown types fail closed),
  9. reserves budget/category/occurrences atomically in the ledger,
 10. and only then asks PayPal to move money,
 11. returning a signed receipt plus the full trace either way.

Only the gateway holds the settlement function, so nothing else in the app can
move money.
"""

from __future__ import annotations

import json
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import date
from typing import Callable

from cryptography.hazmat.primitives.asymmetric import ec

from loopremit.crypto import jws, sdjwt
from loopremit.crypto.jwk import load_public_jwk, public_jwk, thumbprint
from loopremit.db import Database
from loopremit.evidence import account_matches, dhash, line_items_sum_ok, line_items_total_minor, sha256_hex, to_minor
from loopremit.mandates import model as m
from loopremit.mandates.closed_mandate import receipt_reference, transaction_id_for
from loopremit.mandates.open_mandate import mandate_id as compute_mandate_id

from .ledger import Ledger, LedgerRejection, Reservation, category_window
from .trace import Rejected, StepUpRequired, Trace

NONCE_TTL = 600
STEP_UP_TYP = "loopremit-step-up+jwt"
STEP_UP_MAX_AGE = 14 * 86_400
NO_LIMIT = 10**15

LABELS = {
    "parse": "Parse the AP2 mandate chain",
    "issuer_signature": "Open mandate signed by the OFW's registered device key",
    "open_disclosures": "Open mandate disclosures match the signed digests",
    "open_validity": "Open mandate type and lifetime (vct, iat, exp)",
    "key_binding": "Closed mandate signed by the agent key in cnf (aud, nonce, iat, sd_hash)",
    "closed_content": "Closed mandate content (vct mandate.payment.1, required fields)",
    "presentation_order": "Previous presentation has a receipt (AP2 one-at-a-time rule)",
    "ledger": "Atomic ledger: replay, duplicate, budget, occurrences, category cap",
    "settlement": "PayPal: charge vaulted wallet (USD), pay out payee (PHP)",
    "receipt": "Signed payment receipt",
}


@dataclass
class Presentation:
    chain: str
    evidence_jwt: str
    step_up_decision: str | None = None


@dataclass
class SettlementRequest:
    transaction_id: str
    payee: dict
    amount_minor: int
    currency: str
    reference: str
    memo: str


@dataclass
class SettlementResult:
    ok: bool
    mode: str = ""
    order_id: str | None = None
    capture_id: str | None = None
    payout_batch_id: str | None = None
    payout_status: str | None = None
    usd_cents: int | None = None
    fx_rate: str | None = None
    fx_source: str | None = None
    error: str | None = None


@dataclass
class GatewayResult:
    outcome: str  # paid | rejected | step_up_required | settlement_failed
    receipt_id: str
    receipt_jwt: str
    receipt: dict
    trace: list[dict]
    mandate_id: str | None = None
    transaction_id: str | None = None
    content: dict | None = None
    error: str | None = None
    error_description: str | None = None
    settlement: SettlementResult | None = None

    @property
    def paid(self) -> bool:
        return self.outcome == "paid"


@dataclass
class _Ctx:
    """What the pipeline has established so far."""

    mandate_id: str | None = None
    mandate_verified: bool = False
    reference: str | None = None
    device_pub: ec.EllipticCurvePublicKey | None = None
    agent_pub: ec.EllipticCurvePublicKey | None = None
    open_content: dict = field(default_factory=dict)
    content: dict | None = None
    budget_minor: int = NO_LIMIT
    max_occurrences: int | None = None
    budget_period: str = "ALL"
    cap: dict | None = None
    image_sha256: str | None = None
    phash: str | None = None
    step_up_needed: bool = False
    step_up_reason: str = ""


class Gateway:
    def __init__(self, db: Database, key: ec.EllipticCurvePrivateKey,
                 settler: Callable[[SettlementRequest], SettlementResult],
                 audience: str = "loopremit-gateway", clock: Callable[[], float] = time.time):
        self.db = db
        self.key = key
        self.settler = settler
        self.audience = audience
        self.clock = clock
        self.ledger = Ledger(db)

    # ------------------------------------------------------------------ public API

    @property
    def jwk(self) -> dict:
        return {**public_jwk(self.key), "kid": thumbprint(public_jwk(self.key)), "use": "sig", "alg": "ES256"}

    def now(self) -> int:
        return int(self.clock())

    def issue_nonce(self) -> str:
        nonce = secrets.token_urlsafe(24)
        self.db.run("INSERT INTO gw_nonces (nonce, issued_at) VALUES (?, ?)", nonce, self.now())
        return nonce

    def latest_receipt(self, mandate_id: str) -> str | None:
        row = self.db.one("SELECT id FROM gw_receipts WHERE mandate_id = ? ORDER BY created_at DESC, rowid DESC "
                          "LIMIT 1", mandate_id)
        return row["id"] if row else None

    def register_evidence(self, image_sha256: str, path: str, mime: str, phash: str) -> None:
        self.db.run("INSERT OR IGNORE INTO gw_evidence (image_sha256, phash, path, mime, created_at) "
                    "VALUES (?,?,?,?,?)", image_sha256, phash, path, mime, self.now())

    def process(self, p: Presentation, bill_id: int | None = None) -> GatewayResult:
        trace, ctx = Trace(), _Ctx()
        try:
            self._verify(p, trace, ctx)
        except StepUpRequired as exc:
            return self._finish(trace, ctx, p, bill_id, "step_up_required", "step_up_required", exc.message)
        except Rejected as exc:
            self._skip_rest(trace)
            return self._finish(trace, ctx, p, bill_id, "rejected", exc.code, exc.message)

        content = ctx.content
        amount = content["payment_amount"]["amount"]
        execution_date = content["execution_date"]
        try:
            entry_id, numbers = self.ledger.reserve(
                mandate_id=ctx.mandate_id, transaction_id=content["transaction_id"],
                image_sha256=ctx.image_sha256, phash=ctx.phash,
                r=Reservation(period=ctx.budget_period, category=content["payee"]["category"],
                              category_window=category_window(ctx.cap, execution_date),
                              amount_minor=amount, budget_minor=ctx.budget_minor,
                              max_occurrences=ctx.max_occurrences, category_max_minor=ctx.cap["max"]))
        except LedgerRejection as exc:
            trace.failed("ledger", LABELS["ledger"], f"{exc.constraint}: {exc.message}", exc.code, stop=False)
            trace.skipped("settlement", LABELS["settlement"])
            return self._finish(trace, ctx, p, bill_id, "rejected", exc.code, exc.message)
        trace.passed("ledger", LABELS["ledger"], _ledger_detail(numbers, amount, ctx))

        result = self.settler(SettlementRequest(
            transaction_id=content["transaction_id"], payee=content["payee"], amount_minor=amount,
            currency=content["payment_amount"]["currency"], reference=ctx.reference,
            memo=f"Loop Remit bill payment to {content['payee']['name']}"))
        if not result.ok:
            self.ledger.release(entry_id)
            trace.failed("settlement", LABELS["settlement"], f"{result.error} (reservation released)",
                         "settlement_failed", stop=False)
            return self._finish(trace, ctx, p, bill_id, "settlement_failed", "settlement_failed",
                                result.error or "settlement failed", result)
        self.ledger.settle(entry_id)
        trace.passed("settlement", LABELS["settlement"],
                     f"[{result.mode}] charged USD {result.usd_cents / 100:,.2f} at {result.fx_rate} PHP/USD "
                     f"({result.fx_source}); capture {result.capture_id}; payout batch {result.payout_batch_id} "
                     f"({result.payout_status})")
        return self._finish(trace, ctx, p, bill_id, "paid", None, None, result)

    # ------------------------------------------------------------------ verification pipeline

    def _verify(self, p: Presentation, trace: Trace, ctx: _Ctx) -> None:
        now = self.now()

        # 1. parse ---------------------------------------------------------------
        try:
            tokens = sdjwt.split_chain(p.chain)
            if len(tokens) != 2:
                raise sdjwt.SDJWTError(f"expected 2 chain segments, got {len(tokens)}")
            open_tok, closed_tok = tokens
            open_header = jws.decode_unverified(open_tok.issuer_jwt).header
            jws.decode_unverified(closed_tok.issuer_jwt)
        except (sdjwt.SDJWTError, jws.JWSError) as exc:
            trace.failed("parse", LABELS["parse"], str(exc), "malformed")
        ctx.reference = receipt_reference(closed_tok.issuer_jwt)
        trace.passed("parse", LABELS["parse"],
                     f"open mandate with {len(open_tok.disclosures)} disclosures ~~ closed mandate hop")

        # 2. issuer signature against a registered device key ----------------------
        kid = open_header.get("kid")
        row = self.db.one("SELECT jwk, created_at FROM device_keys WHERE kid = ? AND revoked = 0", kid) if kid else None
        if row is None:
            trace.failed("issuer_signature", LABELS["issuer_signature"],
                         f"kid {str(kid)[:12]}… is not a registered OFW device key", "unknown_device_key")
        ctx.device_pub = load_public_jwk(json.loads(row["jwk"]))
        try:
            jws.verify(open_tok.issuer_jwt, ctx.device_pub, expected_typ=m.ISSUER_TYP)
        except jws.JWSError as exc:
            trace.failed("issuer_signature", LABELS["issuer_signature"], str(exc), "bad_issuer_signature")
        ctx.mandate_id, ctx.mandate_verified = compute_mandate_id(open_tok), True
        trace.passed("issuer_signature", LABELS["issuer_signature"], f"ES256 verified with device key {kid[:12]}…")

        # 3. open disclosures ----------------------------------------------------
        try:
            claims = sdjwt.verify(open_tok, ctx.device_pub, expected_typ=m.ISSUER_TYP).claims
            delegate = claims.get("delegate_payload")
            if not (isinstance(delegate, list) and len(delegate) == 1 and isinstance(delegate[0], dict)):
                raise sdjwt.SDJWTError("delegate_payload must disclose exactly one mandate")
        except sdjwt.SDJWTError as exc:
            trace.failed("open_disclosures", LABELS["open_disclosures"], str(exc), "bad_disclosure")
        ctx.open_content = open_content = delegate[0]
        trace.passed("open_disclosures", LABELS["open_disclosures"],
                     f"{len(open_tok.disclosures)} presented disclosures, every digest found in the signed payload")

        # 4. open mandate validity -------------------------------------------------
        if open_content.get("vct") != m.OPEN_VCT:
            trace.failed("open_validity", LABELS["open_validity"], f"vct {open_content.get('vct')!r}", "bad_open_mandate")
        exp, iat = open_content.get("exp"), open_content.get("iat")
        if not isinstance(exp, int) or not isinstance(iat, int):
            trace.failed("open_validity", LABELS["open_validity"], "iat/exp missing", "bad_open_mandate")
        if exp <= now:
            trace.failed("open_validity", LABELS["open_validity"],
                         f"open mandate expired {_ago(now - exp)} ago", "mandate_expired")
        if iat > now + 60:
            trace.failed("open_validity", LABELS["open_validity"], "iat is in the future", "bad_open_mandate")
        try:
            ctx.agent_pub = load_public_jwk(open_content["cnf"]["jwk"])
        except (KeyError, TypeError, ValueError) as exc:
            trace.failed("open_validity", LABELS["open_validity"], f"cnf.jwk unusable: {exc}", "bad_open_mandate")
        trace.passed("open_validity", LABELS["open_validity"],
                     f"{m.OPEN_VCT}, expires in {_ago(exp - now)}, cnf names agent key "
                     f"{thumbprint(open_content['cnf']['jwk'])[:12]}…")

        # 5. key binding: closed hop signed by the cnf key, bound to this presentation
        try:
            closed_jws = jws.verify(closed_tok.issuer_jwt, ctx.agent_pub, expected_typ=sdjwt.KB_SD_JWT_TYP)
        except jws.JWSError as exc:
            trace.failed("key_binding", LABELS["key_binding"],
                         f"closed mandate not signed by the agent key in cnf ({exc})", "bad_agent_signature")
        nonce = closed_jws.payload.get("nonce")
        try:
            sdjwt.check_binding(closed_jws.payload, open_tok, self.audience, nonce, now, max_age=300)
        except sdjwt.SDJWTError as exc:
            trace.failed("key_binding", LABELS["key_binding"], str(exc), "bad_key_binding")
        if not self._consume_nonce(nonce, now):
            trace.failed("key_binding", LABELS["key_binding"],
                         "nonce unknown, expired or already used (replayed presentation)", "replay")
        trace.passed("key_binding", LABELS["key_binding"],
                     f"aud={self.audience}, single-use nonce consumed, sd_hash matches the open presentation")

        # 6. closed mandate content ----------------------------------------------------
        try:
            closed_claims = sdjwt.resolve(closed_jws.payload, closed_tok.disclosures)
            content = (closed_claims.get("delegate_payload") or [None])[0]
            _check_closed_content(content)
        except (sdjwt.SDJWTError, ValueError) as exc:
            trace.failed("closed_content", LABELS["closed_content"], str(exc), "bad_closed_mandate")
        ctx.content = content
        amount = content["payment_amount"]
        trace.passed("closed_content", LABELS["closed_content"],
                     f"{amount['currency']} {amount['amount'] / 100:,.2f} to {content['payee'].get('name')} "
                     f"on {content['execution_date']}")

        # 7. receipt chain ---------------------------------------------------------
        prev, latest = closed_claims.get("loopremit_prev_receipt"), self.latest_receipt(ctx.mandate_id)
        if prev != latest:
            trace.failed("presentation_order", LABELS["presentation_order"],
                         f"presentation references receipt {str(prev)[:10]}…, latest is {str(latest)[:10]}…",
                         "presentation_order")
        trace.passed("presentation_order", LABELS["presentation_order"],
                     "first presentation of this mandate" if latest is None else f"follows receipt {latest[:10]}…")

        # 8. constraints -----------------------------------------------------------
        failures = []
        for constraint in open_content.get("constraints", []):
            ctype = constraint.get("type") if isinstance(constraint, dict) else None
            step, label = f"c:{ctype}", f"Constraint {ctype}"
            evaluator = self._evaluators().get(ctype)
            if evaluator is None:
                trace.failed(step, label, "unknown constraint type: fails closed", "unknown_constraint", stop=False)
                failures.append(("unknown_constraint", f"unknown constraint {ctype}"))
                continue
            ok, detail, code = evaluator(constraint, ctx, p)
            if ok:
                trace.passed(step, label, detail)
            else:
                trace.failed(step, label, detail, code, stop=False)
                failures.append((code, detail))
        if failures:
            raise Rejected(*failures[0])
        if ctx.image_sha256 is None:
            raise Rejected("evidence_required", "Loop Remit only pays bills with evidence (loopremit.evidence_required)")
        if ctx.cap is None:  # no category_cap constraint: no per-category limit
            ctx.cap = {"category": ctx.content["payee"].get("category", "other"), "max": NO_LIMIT, "period": "MONTHLY"}
        if ctx.step_up_needed:
            raise StepUpRequired(f"{ctx.step_up_reason}: waiting for the OFW's signature")

    # ------------------------------------------------------------------ constraint evaluators
    # Each returns (ok, human-readable detail, error code).

    def _evaluators(self):
        return {
            m.ALLOWED_PAYEES: self._allowed_payees,
            m.AMOUNT_RANGE: self._amount_range,
            m.BUDGET: self._budget,
            m.AGENT_RECURRENCE: self._recurrence,
            m.EXECUTION_DATE: self._execution_date,
            m.CATEGORY_CAP: self._category_cap,
            m.EVIDENCE_REQUIRED: self._evidence,
            m.STEP_UP_OVER: self._step_up,
        }

    def _allowed_payees(self, c, ctx, p):
        payee = ctx.content["payee"]
        allowed = c.get("allowed", [])
        if payee in allowed:
            return True, f"{payee['name']} is an allowed payee ({len(allowed)} disclosed, the rest stay hidden)", None
        return False, f"payee not in allowed_payees: {payee.get('name')!r} ({payee.get('id')})", "payee_not_allowed"

    def _amount_range(self, c, ctx, p):
        amt = ctx.content["payment_amount"]
        if amt["currency"] != c.get("currency"):
            return False, f"currency {amt['currency']} != {c.get('currency')}", "currency_mismatch"
        lo, hi = c.get("min", 0), c["max"]
        if not lo <= amt["amount"] <= hi:
            return False, f"{amt['amount'] / 100:,.2f} outside [{lo / 100:,.2f}, {hi / 100:,.2f}]", "amount_out_of_range"
        return True, f"{amt['amount'] / 100:,.2f} within [{lo / 100:,.2f}, {hi / 100:,.2f}] {c['currency']}", None

    def _budget(self, c, ctx, p):
        if c.get("currency") != ctx.content["payment_amount"]["currency"]:
            return False, "budget currency mismatch", "currency_mismatch"
        ctx.budget_minor = m.budget_max_minor(c)
        return True, f"budget {c['max']:,.2f} {c['currency']} per window (spend checked atomically in the ledger)", None

    def _recurrence(self, c, ctx, p):
        if c.get("frequency") != "MONTHLY":
            return False, f"unsupported frequency {c.get('frequency')!r}", "unsupported_recurrence"
        ctx.budget_period = ctx.content["execution_date"][:7]
        ctx.max_occurrences = c.get("max_occurrences")
        return True, f"monthly window {ctx.budget_period}, max {ctx.max_occurrences} payments (counted in the ledger)", None

    def _execution_date(self, c, ctx, p):
        day = ctx.content["execution_date"]
        if c.get("not_before") and day < c["not_before"]:
            return False, f"execution_date {day} is before {c['not_before']}", "outside_execution_window"
        if c.get("not_after") and day > c["not_after"]:
            return False, f"execution_date {day} is after {c['not_after']}", "outside_execution_window"
        return True, f"{day} within {c.get('not_before')} .. {c.get('not_after')}", None

    def _category_cap(self, c, ctx, p):
        category = ctx.content["payee"].get("category")
        cap = next((x for x in c.get("caps", []) if x.get("category") == category), None)
        if cap is None:
            return False, f"no disclosed cap for category {category!r}", "category_not_allowed"
        if cap.get("currency") != ctx.content["payment_amount"]["currency"]:
            return False, "cap currency mismatch", "currency_mismatch"
        day = ctx.content["execution_date"]
        if cap.get("period") == "WINDOW" and not (cap["not_before"] <= day <= cap["not_after"]):
            return False, f"{day} outside the {category} cap window", "outside_category_window"
        ctx.cap = cap
        window = cap.get("label") or ("per month" if cap.get("period") == "MONTHLY" else "per window")
        return True, f"{category} cap {cap['max'] / 100:,.2f} {cap['currency']} {window} (spend checked in the ledger)", None

    def _evidence(self, c, ctx, p):
        try:
            ev = jws.verify(p.evidence_jwt, ctx.agent_pub, expected_typ=m.EVIDENCE_TYP).payload
        except jws.JWSError as exc:
            return False, f"evidence JWT not signed by the agent key: {exc}", "bad_evidence"
        if transaction_id_for(p.evidence_jwt) != ctx.content["transaction_id"]:
            return False, "transaction_id is not the hash of the presented evidence", "evidence_mismatch"
        row = self.db.one("SELECT path FROM gw_evidence WHERE image_sha256 = ?", ev.get("image_sha256"))
        if row is None:
            return False, "bill image not in the evidence store", "evidence_missing"
        with open(row["path"], "rb") as fh:
            data = fh.read()
        if sha256_hex(data) != ev["image_sha256"]:
            return False, "stored bill image does not match its hash", "evidence_tampered"
        ctx.image_sha256, ctx.phash = ev["image_sha256"], dhash(data)

        extraction, amount = ev.get("extraction") or {}, ctx.content["payment_amount"]
        problems = []
        if extraction.get("currency") != amount["currency"] or to_minor(extraction.get("amount_due", 0)) != amount["amount"]:
            problems.append(("amount_mismatch", "extracted bill total does not equal payment_amount"))
        for check in c.get("checks", []):
            if check == "payee_account_match" and not account_matches(extraction, ctx.content["payee"]):
                problems.append(("account_mismatch",
                                 f"bill account {extraction.get('account_number')!r} does not match the payee's"))
            elif check == "line_items_sum" and not line_items_sum_ok(extraction):
                problems.append(("line_items_mismatch",
                                 f"line items sum to {line_items_total_minor(extraction) / 100:,.2f}, "
                                 f"bill says {to_minor(extraction.get('amount_due', 0)) / 100:,.2f}"))
            elif check not in m.EVIDENCE_CHECKS:
                problems.append(("unknown_evidence_check", f"unknown check {check!r}"))
        if problems:
            return False, "; ".join(msg for _, msg in problems), problems[0][0]
        return True, (f"bill image sha-256 {ev['image_sha256'][:12]}… re-hashed; checks re-run: "
                      f"{', '.join(c.get('checks', []))} (no_duplicate in the ledger)"), None

    def _step_up(self, c, ctx, p):
        amount = ctx.content["payment_amount"]["amount"]
        threshold = c["amount"]
        warnings = self._evidence_warnings(p, ctx)
        if amount <= threshold and not warnings:
            return True, f"{amount / 100:,.2f} <= step-up threshold {threshold / 100:,.2f}: agent signature suffices", None
        if not p.step_up_decision:
            ctx.step_up_needed = True
            if amount > threshold:
                ctx.step_up_reason = "amount is over the OFW's step-up threshold"
                return True, f"{amount / 100:,.2f} > {threshold / 100:,.2f}: needs the OFW's signature", None
            ctx.step_up_reason = "this bill carries warnings (possible tampering or instructions aimed at the AI)"
            return True, f"signed evidence carries {len(warnings)} warning(s): needs the OFW's signature", None
        try:
            decision = jws.verify(p.step_up_decision, ctx.device_pub, expected_typ=STEP_UP_TYP).payload
        except jws.JWSError as exc:
            return False, f"step-up decision not signed by the OFW device key: {exc}", "bad_step_up"
        if decision.get("vct") != m.STEP_UP_VCT or decision.get("closed_mandate") != ctx.content:
            return False, "OFW signed a different closed mandate", "bad_step_up"
        if not isinstance(decision.get("iat"), int) or decision["iat"] < self.now() - STEP_UP_MAX_AGE:
            return False, "step-up decision is too old", "bad_step_up"
        if decision.get("decision") != "approve":
            return False, "the OFW declined this payment", "declined_by_ofw"
        return True, "OFW approved by signing this exact closed mandate with the device key (human present)", None

    @staticmethod
    def _evidence_warnings(p, ctx) -> list[str]:
        """Warnings in the agent-signed evidence. They can only add a human, never
        remove a check. Bad evidence returns none here because _evidence rejects it."""
        try:
            payload = jws.verify(p.evidence_jwt, ctx.agent_pub, expected_typ=m.EVIDENCE_TYP).payload
        except jws.JWSError:
            return []
        extraction = payload.get("extraction") or {}
        return [*(extraction.get("tampering_signals") or []), *(extraction.get("embedded_instructions") or [])]

    # ------------------------------------------------------------------ after settlement

    def reverse_failed_payout(self, transaction_id: str, capture_id: str) -> str:
        """PayPal took the charge but the payout later failed: refund it and, once
        the refund succeeds, give the budget back. Returns what happened."""
        refunded, note = self.settler.refund(transaction_id, capture_id)
        if refunded:
            self.ledger.reverse(transaction_id)
        return note

    # ------------------------------------------------------------------ helpers

    def _consume_nonce(self, nonce, now: int) -> bool:
        if not isinstance(nonce, str):
            return False
        with self.db.connect() as conn:
            cur = conn.execute("UPDATE gw_nonces SET used_at = ? WHERE nonce = ? AND used_at IS NULL "
                               "AND issued_at >= ?", (now, nonce, now - NONCE_TTL))
            return cur.rowcount == 1

    def _skip_rest(self, trace: Trace) -> None:
        done = {s["step"] for s in trace.steps}
        for step in ("ledger", "settlement"):
            if step not in done:
                trace.skipped(step, LABELS[step])

    def _finish(self, trace: Trace, ctx: _Ctx, p: Presentation, bill_id, outcome: str,
                error: str | None, description: str | None,
                settlement: SettlementResult | None = None) -> GatewayResult:
        content = ctx.content or {}
        receipt = {
            "status": "Success" if outcome == "paid" else "Error",
            "iss": self.audience,
            "iat": self.now(),
            "reference": ctx.reference or sha256_hex(p.chain.encode()),
            "payment_id": f"pay_{uuid.uuid4().hex[:20]}",
        }
        if outcome == "paid":
            receipt["psp_confirmation_id"] = settlement.capture_id
            receipt["network_confirmation_id"] = settlement.payout_batch_id
        else:
            receipt["error"] = error
            receipt["error_description"] = description
        receipt["loopremit"] = {
            "mandate_id": ctx.mandate_id if ctx.mandate_verified else None,
            "transaction_id": content.get("transaction_id"),
            "payee_id": (content.get("payee") or {}).get("id"),
            "amount": content.get("payment_amount"),
            "usd_charged_cents": settlement.usd_cents if settlement and settlement.ok else None,
            "fx_rate": settlement.fx_rate if settlement and settlement.ok else None,
            "outcome": outcome,
        }
        receipt_jwt = jws.sign({"typ": m.RECEIPT_TYP, "kid": self.jwk["kid"]}, receipt, self.key)
        receipt_id = sha256_hex(receipt_jwt.encode())[:32]
        trace.passed("receipt", LABELS["receipt"], f"{receipt['status']} receipt {receipt_id[:10]}… signed by the gateway key")
        self.db.run(
            "INSERT INTO gw_receipts (id, mandate_id, transaction_id, bill_id, status, error, receipt_jwt, trace, "
            "presentation, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            receipt_id, ctx.mandate_id if ctx.mandate_verified else None, content.get("transaction_id"), bill_id,
            receipt["status"], error, receipt_jwt, json.dumps(trace.to_list()),
            json.dumps({"chain": p.chain, "evidence_jwt": p.evidence_jwt, "step_up_decision": p.step_up_decision}),
            receipt["iat"])
        return GatewayResult(outcome=outcome, receipt_id=receipt_id, receipt_jwt=receipt_jwt, receipt=receipt,
                             trace=trace.to_list(), mandate_id=ctx.mandate_id, transaction_id=content.get("transaction_id"),
                             content=ctx.content, error=error, error_description=description, settlement=settlement)


def _check_closed_content(content) -> None:
    if not isinstance(content, dict):
        raise ValueError("closed mandate content missing")
    if content.get("vct") != m.CLOSED_VCT:
        raise ValueError(f"vct {content.get('vct')!r}, wanted {m.CLOSED_VCT}")
    for name in ("transaction_id", "payee", "payment_amount", "payment_instrument", "execution_date"):
        if name not in content:
            raise ValueError(f"closed mandate is missing {name}")
    if "cnf" in content:
        raise ValueError("a terminal (closed) mandate must not carry cnf")
    amount = content["payment_amount"]
    if not isinstance(amount.get("amount"), int) or amount["amount"] <= 0 or not isinstance(amount.get("currency"), str):
        raise ValueError("payment_amount must be a positive integer in minor units")
    if not isinstance(content["payee"], dict) or "name" not in content["payee"]:
        raise ValueError("payee must be a Merchant object")
    date.fromisoformat(content["execution_date"])


def _ago(seconds: int) -> str:
    seconds = abs(seconds)
    if seconds >= 86_400:
        return f"{seconds // 86_400}d"
    if seconds >= 3600:
        return f"{seconds // 3600}h"
    return f"{seconds // 60}m"


def _ledger_detail(numbers: dict, amount: int, ctx: _Ctx) -> str:
    budget_left = numbers["budget_minor"] - numbers["budget_spent_before"] - amount
    cap_left = numbers["category_max_minor"] - numbers["category_spent_before"] - amount
    return (f"reserved {amount / 100:,.2f}; budget left this month {budget_left / 100:,.2f}; "
            f"{ctx.content['payee']['category']} cap left {cap_left / 100:,.2f}")
