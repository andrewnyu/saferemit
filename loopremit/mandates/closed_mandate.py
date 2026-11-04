"""Closed Payment Mandate (vct `mandate.payment.1`), signed by the bill agent.

In AP2's autonomous (human-not-present) flow the agent proves it may use the
open mandate by appending a terminal delegation hop: an SD-JWT signed with the
key in the open mandate's `cnf` claim (`typ: kb+sd-jwt`). Its payload holds the
key-binding claims (`aud`, `nonce`, `iat`, `sd_hash` over the open presentation)
and a `delegate_payload` whose disclosure is the closed mandate content.

    <open issuer JWT>~<open content>~<payee i>~<cap j>~~<closed hop JWT>~<closed content>~

Only the disclosures the gateway needs are presented: the open mandate content,
the one payee being paid, and the one category cap that applies. The other
payees and caps stay hidden (AP2: "present only the disclosures needed").
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec

from loopremit.crypto import jws, sdjwt
from loopremit.crypto.b64 import b64url_encode
from loopremit.crypto.sdjwt import SD

from .model import CLOSED_VCT, EVIDENCE_TYP, PAYMENT_INSTRUMENT


def evidence_jwt(agent_key: ec.EllipticCurvePrivateKey, *, image_sha256: str, phash: str,
                 extraction: dict, extraction_source: str, iat: int) -> str:
    """The agent-signed bill evidence. It plays the role of AP2's checkout JWT."""
    payload = {"iat": iat, "image_sha256": image_sha256, "phash": phash,
               "extraction": extraction, "extraction_source": extraction_source}
    return jws.sign({"typ": EVIDENCE_TYP}, payload, agent_key)


def transaction_id_for(evidence: str) -> str:
    """AP2: transaction_id is the base64url hash of the checkout JWT. Ours is the
    hash of the evidence JWT, which binds the payment to one bill image."""
    return b64url_encode(hashlib.sha256(evidence.encode("ascii")).digest())


def closed_mandate_content(*, transaction_id: str, payee: dict, amount_minor: int,
                           currency: str, execution_date: str) -> dict:
    return {
        "vct": CLOSED_VCT,
        "transaction_id": transaction_id,
        "payee": payee,
        "payment_amount": {"amount": amount_minor, "currency": currency},
        "payment_instrument": dict(PAYMENT_INSTRUMENT),
        "execution_date": execution_date,
    }


def select_disclosures(open_token: sdjwt.SdJwt, payee: dict, category: str | None) -> sdjwt.SdJwt:
    """Present the open mandate with the minimum disclosures for this payment."""
    keep = []
    for d in open_token.decoded_disclosures():
        value = d.value
        if isinstance(value, dict) and "vct" in value:  # the open mandate content itself
            keep.append(d.digest)
        elif isinstance(value, dict) and value == payee:  # exactly this payee
            keep.append(d.digest)
        elif isinstance(value, dict) and "period" in value and value.get("category") == category:
            keep.append(d.digest)
    return sdjwt.present(open_token, keep)


@dataclass
class ClosedPresentation:
    chain: str  # open presentation ~~ closed hop
    closed_jwt: str  # the closed hop's issuer JWT; receipts reference its hash


def build_presentation(*, open_token: sdjwt.SdJwt, agent_key: ec.EllipticCurvePrivateKey,
                       content: dict, aud: str, nonce: str, iat: int,
                       prev_receipt: str | None) -> ClosedPresentation:
    category = content["payee"].get("category")
    open_presentation = select_disclosures(open_token, content["payee"], category)
    claims = {"delegate_payload": [SD(content)], "loopremit_prev_receipt": prev_receipt}
    closed = sdjwt.create_kb_sd_jwt(open_presentation, agent_key, claims, aud=aud, nonce=nonce, iat=iat)
    return ClosedPresentation(sdjwt.join_chain([open_presentation, closed]), closed.issuer_jwt)


def receipt_reference(closed_jwt: str) -> str:
    """AP2 receipts reference the hash of the closed mandate (the leaf JWT)."""
    return b64url_encode(hashlib.sha256(closed_jwt.encode("ascii")).digest())
