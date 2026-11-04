"""Server-side signing keys: the bill agent's key and the gateway's receipt key.

They are separate keys on purpose. The agent key is what the open mandate's
`cnf` names; the gateway key only signs receipts. Neither can sign as the OFW:
the OFW's key lives in the browser and is never exportable.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from padala.crypto.jwk import generate_private_key, private_key_from_pem, private_key_to_pem


def load_or_create(path: Path) -> ec.EllipticCurvePrivateKey:
    if path.exists():
        return private_key_from_pem(path.read_bytes())
    path.parent.mkdir(parents=True, exist_ok=True)
    key = generate_private_key()
    path.write_bytes(private_key_to_pem(key))
    path.chmod(0o600)
    return key
