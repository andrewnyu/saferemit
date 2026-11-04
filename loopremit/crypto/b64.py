"""base64url without padding (RFC 7515 §2), the encoding used everywhere in JOSE."""

import base64
import re

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url. Rejects padding and non-alphabet characters
    instead of silently skipping them, so a tampered token cannot smuggle bytes."""
    if not isinstance(text, str) or not _B64URL_RE.match(text):
        raise ValueError("invalid base64url")
    if len(text) % 4 == 1:
        raise ValueError("invalid base64url length")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
