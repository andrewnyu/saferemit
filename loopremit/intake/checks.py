"""Deterministic checks the bill agent runs on every extraction.

They explain the agent's draft to the family and the OFW. None of them can
approve a payment: the gateway re-runs the ones that matter from signed evidence.
"""

from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass
from datetime import date

from loopremit.evidence import (
    DUPLICATE_DISTANCE, account_matches, hamming, has_line_items, line_items_sum_ok, line_items_total_minor,
    normalize_name, to_minor,
)

ROBUST_Z_FLAG = 3.5  # Iglewicz & Hoaglin's usual cut-off for the modified z-score
YOY_FLAG_PCT = 50  # also flag a +/-50% swing against the same month last year


@dataclass
class Check:
    name: str
    result: str  # pass | warn | fail
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def match_payee(biller_name: str, payees: list[dict]) -> dict | None:
    """Registry match on the biller's name or a known alias (normalized)."""
    wanted = normalize_name(biller_name)
    for payee in payees:
        names = [payee["name"], *payee.get("aliases", [])]
        if any(normalize_name(n) == wanted for n in names):
            return payee
    return None


def _modified_z(x: float, values: list[float]) -> float | None:
    if len(values) < 3:
        return None
    med = statistics.median(values)
    mad = statistics.median(abs(v - med) for v in values)
    if mad == 0:
        return None
    return 0.6745 * (x - med) / mad


def seasonal_anomaly(amount_minor: int, period: str, history: dict[str, int]) -> dict:
    """Anomaly score against per-payee seasonal history.

    Bills here are seasonal (tuition peaks in June/August and at semester start,
    power peaks in the hot months), so the raw amount is compared with a
    *deseasonalized* history: each month gets a seasonal index
    (median of that calendar month / overall median), every value is divided by
    its month's index, and the current bill gets a modified z-score
    0.6745 * (x - median) / MAD on that scale. Also reports the change against
    the same month last year, which is what people actually understand.
    """
    if not history:
        return {"score": None, "flag": False, "message": "no history for this payee yet"}
    overall = statistics.median(history.values())
    by_month: dict[str, list[int]] = {}
    for p, v in history.items():
        by_month.setdefault(p[5:7], []).append(v)
    index = {mm: statistics.median(vs) / overall for mm, vs in by_month.items()}
    month = period[5:7]
    seasonal = [v / index[p[5:7]] for p, v in history.items()]
    current = amount_minor / index.get(month, 1.0)
    z = _modified_z(current, seasonal)

    last_year = f"{int(period[:4]) - 1}{period[4:]}"
    parts = []
    pct = None
    if last_year in history:
        pct = round(100 * (amount_minor - history[last_year]) / history[last_year])
        label = date.fromisoformat(last_year + "-01").strftime("%b %Y")
        parts.append(f"{pct:+d}% vs {label} (₱{history[last_year] / 100:,.2f})")
    if z is not None:
        parts.append(f"seasonally adjusted modified z = {z:.1f}")
    flag = (z is not None and abs(z) > ROBUST_Z_FLAG) or (pct is not None and abs(pct) >= YOY_FLAG_PCT)
    return {"score": None if z is None else round(z, 2), "pct_vs_last_year": pct, "flag": flag,
            "message": "; ".join(parts) or "not enough history"}


def run_checks(extraction: dict, *, payees: list[dict], history: dict[str, int], period: str,
               phash: str, prior_bills: list[dict]) -> tuple[dict | None, list[Check], dict]:
    """Returns (matched payee or None, checks, anomaly)."""
    checks: list[Check] = []
    payee = match_payee(extraction["biller_name"], payees)
    if payee:
        checks.append(Check("payee_registry", "pass", f"{payee['name']} is a registered payee"))
        if account_matches(extraction, payee):
            checks.append(Check("account_match", "pass", f"account {extraction['account_number']} matches history"))
        else:
            checks.append(Check("account_match", "fail",
                                f"account {extraction.get('account_number')!r} does not match "
                                f"{payee['account_number']!r} on file"))
    else:
        checks.append(Check("payee_registry", "fail",
                            f"{extraction['biller_name']!r} is not a registered payee"))

    total = to_minor(extraction["amount_due"])
    items = line_items_total_minor(extraction)
    if not has_line_items(extraction):
        checks.append(Check("line_items_sum", "warn",
                            f"no line items on this bill, so nothing to check the ₱{total / 100:,.2f} total against"))
    elif line_items_sum_ok(extraction):
        checks.append(Check("line_items_sum", "pass", f"{len(extraction['line_items'])} line items sum to ₱{total / 100:,.2f}"))
    else:
        checks.append(Check("line_items_sum", "fail",
                            f"line items sum to ₱{items / 100:,.2f} but the bill says ₱{total / 100:,.2f}"))

    anomaly = seasonal_anomaly(total, period, history) if payee else {"score": None, "flag": False,
                                                                       "message": "unknown payee: no history"}
    checks.append(Check("seasonal_anomaly", "warn" if anomaly["flag"] else "pass", anomaly["message"]))

    duplicate = next((b for b in prior_bills if b.get("phash") and hamming(b["phash"], phash) <= DUPLICATE_DISTANCE), None)
    if duplicate:
        checks.append(Check("duplicate", "fail", f"looks like bill #{duplicate['id']} (perceptual hash match)"))
    else:
        checks.append(Check("duplicate", "pass", "no perceptual-hash match among earlier bills"))

    for signal in extraction.get("tampering_signals") or []:
        checks.append(Check("tampering", "warn", signal))
    for text in extraction.get("embedded_instructions") or []:
        checks.append(Check("prompt_injection", "fail", f"instructions embedded in the bill were ignored: {text!r}"))
    return payee, checks, anomaly
