"""Deterministic bill checks shared by the bill agent and the gateway.

The agent runs them to explain its draft to the family and the OFW. The gateway
runs them again, independently, from the signed evidence and the stored image,
because it must never trust the agent's own conclusions.
"""

from __future__ import annotations

import hashlib
import io
import re
from decimal import ROUND_HALF_UP, Decimal

from PIL import Image

DUPLICATE_DISTANCE = 30  # of 256 dHash bits; re-photographed copies of the samples differ by ~20,
#                          different bills by 40+


def to_minor(amount: float | int | str | Decimal) -> int:
    """Pesos (major units, as extracted) to centavos, exactly."""
    return int((Decimal(str(amount)) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_account(value: str | None) -> str:
    return re.sub(r"[^0-9A-Z]", "", (value or "").upper())


def normalize_name(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()


def account_matches(extraction: dict, payee: dict) -> bool:
    got = normalize_account(extraction.get("account_number"))
    return bool(got) and got == normalize_account(payee.get("account_number"))


def line_items_total_minor(extraction: dict) -> int:
    return sum(to_minor(item["amount"]) for item in extraction.get("line_items", []))


def line_items_sum_ok(extraction: dict) -> bool:
    items = extraction.get("line_items") or []
    return bool(items) and line_items_total_minor(extraction) == to_minor(extraction["amount_due"])


def dhash(image_bytes: bytes, size: int = 16) -> str:
    """Difference hash: shrink to (size+1) x size greyscale and record whether
    each pixel is brighter than its right neighbour. Robust to re-encoding,
    small crops and lighting. 16x16 = 256 bits (64 hex characters): documents are
    mostly white paper, so the classic 64-bit hash collides too easily."""
    image = Image.open(io.BytesIO(image_bytes)).convert("L").resize((size + 1, size), Image.LANCZOS)
    pixels = image.tobytes()  # one byte per pixel in mode "L"
    bits = 0
    for row in range(size):
        for col in range(size):
            left = pixels[row * (size + 1) + col]
            right = pixels[row * (size + 1) + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return f"{bits:0{size * size // 4}x}"


def hamming(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")
