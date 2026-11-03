"""Open Payment Mandate (vct `mandate.payment.open.1`) as an SD-JWT.

Shape, following the AP2 examples:

    issuer-signed JWT payload          disclosures
    -------------------------          -----------
    {"iss": "padala:ofw-device",       [salt, {vct, constraints, cnf, iat, exp}]  <- open mandate content
     "iat": ...,                       [salt, payee 1] [salt, payee 2] ...        <- allowed_payees elements
     "delegate_payload": [{"...": d}], [salt, cap 1] [salt, cap 2] ...           <- category_cap elements
     "_sd_alg": "sha-256"}

The OFW's browser signs it with a non-extractable WebCrypto key, so the server
only *prepares* a draft (header, payload, disclosures). The browser recomputes
every digest, renders the plan from the decoded disclosures, and signs the exact
bytes it rendered. `finalize()` then attaches the signature.
"""

from __future__ import annotations

import calendar
import hashlib
from dataclasses import dataclass
from datetime import date

from cryptography.hazmat.primitives.asymmetric import ec

from padala.crypto import jws, sdjwt
from padala.crypto.b64 import b64url_encode
from padala.crypto.sdjwt import SD

from .model import (
    AGENT_RECURRENCE, ALLOWED_PAYEES, AMOUNT_RANGE, BUDGET, CATEGORY_CAP, EVIDENCE_CHECKS,
    EVIDENCE_REQUIRED, EXECUTION_DATE, ISSUER_TYP, OPEN_VCT, STEP_UP_OVER, Plan,
)

DAY = 86_400


def open_mandate_content(plan: Plan, agent_jwk: dict, iat: int) -> dict:
    """The mandate content with SD markers on every payee and every cap."""
    # Short-lived on purpose (AP2 recommends the smallest workable `exp`):
    # the earlier of `valid_days` from now and the end of the execution window.
    end_of_window = calendar.timegm(date.fromisoformat(plan.not_after).timetuple()) + DAY
    exp = max(min(iat + plan.valid_days * DAY, end_of_window), iat + DAY)
    return {
        "vct": OPEN_VCT,
        "constraints": [
            {"type": ALLOWED_PAYEES, "allowed": [SD(p.as_merchant()) for p in plan.payees]},
            {"type": AMOUNT_RANGE, "currency": plan.currency,
             "min": plan.amount_min_minor, "max": plan.amount_max_minor},
            {"type": BUDGET, "max": round(plan.monthly_budget_minor / 100, 2), "currency": plan.currency},
            {"type": AGENT_RECURRENCE, "frequency": "MONTHLY",
             "max_occurrences": plan.max_payments_per_month},
            {"type": EXECUTION_DATE, "not_before": plan.not_before, "not_after": plan.not_after},
            {"type": CATEGORY_CAP, "caps": [SD(c.as_constraint_element(plan.currency)) for c in plan.caps]},
            {"type": EVIDENCE_REQUIRED, "alg": "sha-256", "checks": list(EVIDENCE_CHECKS)},
            {"type": STEP_UP_OVER, "amount": plan.step_up_over_minor, "currency": plan.currency},
        ],
        "cnf": {"jwk": agent_jwk},
        "iat": iat,
        "exp": exp,
    }


@dataclass
class Draft:
    """Everything the Trusted Surface (browser) needs to show and sign."""

    header: dict
    payload: dict
    disclosures: list[str]

    @property
    def signing_input(self) -> str:
        return jws.signing_input(self.header, self.payload)

    def to_dict(self) -> dict:
        return {"header": self.header, "payload": self.payload, "disclosures": self.disclosures,
                "signing_input": self.signing_input}


def prepare(plan: Plan, agent_jwk: dict, device_kid: str, iat: int) -> Draft:
    claims = {
        "iss": "padala:ofw-device",
        "iat": iat,
        "delegate_payload": [SD(open_mandate_content(plan, agent_jwk, iat))],
    }
    payload, disclosures = sdjwt.build_payload(claims)
    payload["_sd_alg"] = sdjwt.SD_ALG
    header = {"alg": "ES256", "typ": ISSUER_TYP, "kid": device_kid}
    return Draft(header, payload, [d.encoded for d in disclosures])


def finalize(draft: Draft, signature_b64url: str) -> sdjwt.SdJwt:
    return sdjwt.SdJwt(jws.assemble(draft.signing_input, signature_b64url), list(draft.disclosures))


def sign_with_software_key(draft: Draft, key: ec.EllipticCurvePrivateKey) -> sdjwt.SdJwt:
    """For tests, seed data and the red-team script only. In the app the OFW's
    browser signs with a non-extractable WebCrypto key."""
    issuer_jwt = jws.sign(draft.header, draft.payload, key)
    return sdjwt.SdJwt(issuer_jwt, list(draft.disclosures))


def mandate_id(token: sdjwt.SdJwt) -> str:
    """Stable id of an open mandate: hash of its issuer-signed JWT."""
    return b64url_encode(hashlib.sha256(token.issuer_jwt.encode("ascii")).digest())
