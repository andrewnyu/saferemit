"""The plan an OFW signs, and the AP2 + Loop Remit constraint vocabulary.

Amounts follow AP2's `Amount` type: integer minor units (centavos for PHP).
The one exception is AP2's own `payment.budget`, whose `max` is a decimal number
in major units in the AP2 schema; we keep that shape for spec fidelity and
convert at the edges (see `budget_max_minor`).

Custom constraint types (AP2 §Extension Points: a unique `type`, a schema with
its selectively-disclosable fields, and an evaluation algorithm):

`loopremit.category_cap`
    {"type": "loopremit.category_cap",
     "caps": [SD({"category": str, "max": int minor, "currency": "PHP",
                  "period": "MONTHLY" | "WINDOW",
                  "not_before"?: "YYYY-MM-DD", "not_after"?: "YYYY-MM-DD",
                  "label"?: str})]}
    Each cap is a selectively-disclosable array element.
    Evaluation: the closed mandate's payee carries a `category`. A disclosed cap
    for that category MUST exist. Spending recorded in the ledger for that
    category in the current period (calendar month of `execution_date` for
    MONTHLY, or the [not_before, not_after] window for WINDOW, which also must
    contain `execution_date`) plus this amount MUST be <= `max`.

`loopremit.evidence_required`
    {"type": "loopremit.evidence_required", "alg": "sha-256",
     "checks": ["payee_account_match", "line_items_sum", "no_duplicate"]}
    The bill evidence is an agent-signed JWT that plays the role of AP2's
    merchant-signed checkout JWT: the closed mandate's `transaction_id` MUST be
    base64url(sha-256(evidence JWT)), just as AP2 binds `transaction_id` to the
    checkout JWT hash. The evidence JWT carries the bill image hash.
    Evaluation: the gateway recomputes the transaction_id, verifies the evidence
    signature with the `cnf` key, re-hashes the stored bill image, and re-runs
    each listed check deterministically (it never trusts the agent's own check
    results). The extracted total MUST equal `payment_amount`.

`loopremit.step_up_over`
    {"type": "loopremit.step_up_over", "amount": int minor, "currency": "PHP"}
    Evaluation: if `payment_amount.amount` > `amount`, or the agent-signed bill
    evidence lists any `tampering_signals` or `embedded_instructions`, the agent's
    signature is not enough. The gateway answers `step_up_required` and the payment
    proceeds only with an OFW device-key signature over the same closed mandate
    content (human-present mode). Warnings can only add this requirement.

Interpretation of `payment.agent_recurrence` for bill pay: AP2 describes spacing
between presentations, which fits subscriptions. A household pays several bills
a month, so Loop Remit reads `frequency: MONTHLY` as the budget window and
`max_occurrences` as the maximum number of payments per window.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date

OPEN_VCT = "mandate.payment.open.1"
CLOSED_VCT = "mandate.payment.1"
STEP_UP_VCT = "loopremit.step_up_decision.1"
ISSUER_TYP = "loopremit+sd-jwt"
EVIDENCE_TYP = "loopremit-evidence+jwt"
RECEIPT_TYP = "loopremit-payment-receipt+jwt"

ALLOWED_PAYEES = "payment.allowed_payees"
AMOUNT_RANGE = "payment.amount_range"
BUDGET = "payment.budget"
AGENT_RECURRENCE = "payment.agent_recurrence"
EXECUTION_DATE = "payment.execution_date"
CATEGORY_CAP = "loopremit.category_cap"
EVIDENCE_REQUIRED = "loopremit.evidence_required"
STEP_UP_OVER = "loopremit.step_up_over"

KNOWN_CONSTRAINTS = {
    ALLOWED_PAYEES, AMOUNT_RANGE, BUDGET, AGENT_RECURRENCE, EXECUTION_DATE,
    CATEGORY_CAP, EVIDENCE_REQUIRED, STEP_UP_OVER,
}
EVIDENCE_CHECKS = ["payee_account_match", "line_items_sum", "no_duplicate"]
CATEGORIES = ["education", "utilities", "medical", "housing", "groceries"]

PAYMENT_INSTRUMENT = {
    "id": "paypal-vault",
    "type": "paypal_wallet",
    "description": "OFW PayPal wallet (vaulted, merchant-initiated)",
}


@dataclass
class Payee:
    """An AP2 Merchant object plus Loop Remit fields the gateway needs."""

    id: str
    name: str
    category: str
    account_number: str
    paypal_email: str
    website: str | None = None

    def as_merchant(self) -> dict:
        merchant = {"id": self.id, "name": self.name}
        if self.website:
            merchant["website"] = self.website
        merchant.update(category=self.category, account_number=self.account_number,
                        paypal_email=self.paypal_email)
        return merchant


@dataclass
class CategoryCap:
    category: str
    max_minor: int
    period: str = "MONTHLY"  # or "WINDOW"
    not_before: str | None = None
    not_after: str | None = None
    label: str | None = None

    def as_constraint_element(self, currency: str) -> dict:
        element = {"category": self.category, "max": self.max_minor, "currency": currency,
                   "period": self.period}
        if self.period == "WINDOW":
            element.update(not_before=self.not_before, not_after=self.not_after)
        if self.label:
            element["label"] = self.label
        return element


@dataclass
class Plan:
    payees: list[Payee]
    monthly_budget_minor: int
    max_payments_per_month: int
    amount_min_minor: int
    amount_max_minor: int
    caps: list[CategoryCap]
    step_up_over_minor: int
    not_before: str
    not_after: str
    valid_days: int = 30
    currency: str = "PHP"
    ofw_name: str = "OFW"
    household: str = "Household"
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Plan":
        data = dict(data)
        data["payees"] = [Payee(**p) for p in data["payees"]]
        data["caps"] = [CategoryCap(**c) for c in data["caps"]]
        return cls(**data)


def budget_max_minor(budget_constraint: dict) -> int:
    """AP2 `payment.budget.max` is a decimal in major units; convert to minor."""
    return int(round(float(budget_constraint["max"]) * 100))


def month_key(day: str) -> str:
    return date.fromisoformat(day).strftime("%Y-%m")
