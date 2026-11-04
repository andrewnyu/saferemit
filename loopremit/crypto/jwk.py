"""P-256 keys as JWKs (RFC 7517) and JWK thumbprints (RFC 7638)."""

import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .b64 import b64url_decode, b64url_encode

_COORD_LEN = 32  # P-256 coordinates are 32 bytes


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> dict:
    """Export the public half of a P-256 key as a minimal JWK."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        key = key.public_key()
    numbers = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(numbers.x.to_bytes(_COORD_LEN, "big")),
        "y": b64url_encode(numbers.y.to_bytes(_COORD_LEN, "big")),
    }


def load_public_jwk(jwk: dict) -> ec.EllipticCurvePublicKey:
    """Parse a public P-256 JWK. Anything else (other curves, private 'd',
    wrong coordinate sizes, points off the curve) is rejected."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("only EC P-256 JWKs are supported")
    if "d" in jwk:
        raise ValueError("refusing a JWK that contains a private key")
    x = b64url_decode(jwk.get("x", ""))
    y = b64url_decode(jwk.get("y", ""))
    if len(x) != _COORD_LEN or len(y) != _COORD_LEN:
        raise ValueError("bad P-256 coordinate length")
    # from_encoded_point validates that the point is on the curve.
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x + y)


def thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint: SHA-256 over the required members in lexicographic
    order, no whitespace. Used as the `kid` of device and agent keys."""
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
    return b64url_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


def private_key_to_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def private_key_from_pem(pem: bytes) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise ValueError("expected a P-256 private key")
    return key
