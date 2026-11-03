"""Compact JWS with ES256 only (RFC 7515 / RFC 7518 §3.4).

ES256 signatures in JOSE are the raw 64-byte r||s concatenation, not DER. That
is also exactly what WebCrypto's ECDSA `sign()` returns, which is why the browser
can produce a JWS that this module verifies without any conversion.
"""

import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .b64 import b64url_decode, b64url_encode


class JWSError(ValueError):
    """Raised for any malformed or unverifiable JWS."""


def json_bytes(obj) -> bytes:
    """The one JSON encoding we sign: compact, UTF-8, key order preserved."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def signing_input(header: dict, payload: dict) -> str:
    return f"{b64url_encode(json_bytes(header))}.{b64url_encode(json_bytes(payload))}"


def der_to_raw(der: bytes) -> bytes:
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def raw_to_der(raw: bytes) -> bytes:
    if len(raw) != 64:
        raise JWSError("ES256 signature must be 64 bytes")
    return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))


def sign(header: dict, payload: dict, key: ec.EllipticCurvePrivateKey) -> str:
    header = {"alg": "ES256", **header}
    if header["alg"] != "ES256":
        raise JWSError("only ES256 is supported")
    data = signing_input(header, payload)
    der = key.sign(data.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    return f"{data}.{b64url_encode(der_to_raw(der))}"


@dataclass(frozen=True)
class DecodedJWS:
    header: dict
    payload: dict
    signing_input: str
    signature: bytes


def decode_unverified(token: str) -> DecodedJWS:
    """Split and parse a compact JWS without checking the signature."""
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        raise JWSError("compact JWS must have three parts")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        signature = b64url_decode(parts[2])
    except ValueError as exc:
        raise JWSError(f"malformed JWS: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JWSError("JWS header and payload must be JSON objects")
    return DecodedJWS(header, payload, f"{parts[0]}.{parts[1]}", signature)


def verify(token: str, key: ec.EllipticCurvePublicKey, expected_typ: str | None = None) -> DecodedJWS:
    """Verify an ES256 compact JWS. The algorithm is pinned: a header asking for
    `none`, HS256 or anything else is rejected before any crypto runs."""
    decoded = decode_unverified(token)
    if decoded.header.get("alg") != "ES256":
        raise JWSError(f"unexpected alg {decoded.header.get('alg')!r}")
    if expected_typ is not None and decoded.header.get("typ") != expected_typ:
        raise JWSError(f"unexpected typ {decoded.header.get('typ')!r}, wanted {expected_typ!r}")
    try:
        key.verify(raw_to_der(decoded.signature), decoded.signing_input.encode("ascii"),
                   ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise JWSError("signature does not verify") from exc
    return decoded


def assemble(signing_input_str: str, raw_signature_b64url: str) -> str:
    """Join a signing input with a signature produced elsewhere (the browser)."""
    return f"{signing_input_str}.{raw_signature_b64url}"
