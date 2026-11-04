"""The gateway's budget ledger.

Budget, occurrence count, category cap, replay and duplicate checks all read the
same rows, so they run inside one `BEGIN IMMEDIATE` transaction together with
the insert of the reservation. Two presentations racing for the last ₱1,000 of a
budget therefore cannot both succeed.

Entry lifecycle: reserved -> settled (PayPal succeeded) | released (it failed).
A settled entry is also released if its payout fails later and the charge is refunded.
"""

from __future__ import annotations

from dataclasses import dataclass

from padala.db import Database, now
from padala.evidence import DUPLICATE_DISTANCE, hamming

ACTIVE = "status IN ('reserved', 'settled')"  # entries that count against limits


@dataclass
class Reservation:
    period: str  # budget window, e.g. "2026-11"
    category: str
    category_window: str  # "M:2026-11" or "W:2026-11-01..2027-03-31"
    amount_minor: int
    budget_minor: int
    max_occurrences: int | None
    category_max_minor: int


class LedgerRejection(Exception):
    def __init__(self, code: str, message: str, constraint: str):
        super().__init__(message)
        self.code, self.message, self.constraint = code, message, constraint


class Ledger:
    def __init__(self, db: Database):
        self.db = db

    def reserve(self, *, mandate_id: str, transaction_id: str, image_sha256: str, phash: str,
                r: Reservation) -> tuple[int, dict]:
        """Atomically check every stateful constraint and reserve the amount.
        Returns (entry id, numbers for the trace)."""
        with self.db.transaction() as conn:
            active = ACTIVE
            if conn.execute(f"SELECT 1 FROM gw_ledger WHERE transaction_id = ? AND {active}",
                            (transaction_id,)).fetchone():
                raise LedgerRejection("replay", "transaction_id was already paid or is in flight", "replay")

            for row in conn.execute(f"SELECT phash, transaction_id FROM gw_ledger WHERE {active}"):
                if hamming(row["phash"], phash) <= DUPLICATE_DISTANCE:
                    raise LedgerRejection("duplicate_bill",
                                          "this bill image matches one that was already paid",
                                          "padala.evidence_required")

            spent, count = conn.execute(
                f"SELECT COALESCE(SUM(amount_minor), 0), COUNT(*) FROM gw_ledger "
                f"WHERE mandate_id = ? AND period = ? AND {active}", (mandate_id, r.period)).fetchone()
            if spent + r.amount_minor > r.budget_minor:
                raise LedgerRejection(
                    "over_budget",
                    f"monthly budget {r.budget_minor / 100:,.2f}: spent {spent / 100:,.2f}, "
                    f"this payment {r.amount_minor / 100:,.2f}", "payment.budget")
            if r.max_occurrences is not None and count + 1 > r.max_occurrences:
                raise LedgerRejection("too_many_payments",
                                      f"{count} payments this month already (max {r.max_occurrences})",
                                      "payment.agent_recurrence")

            (cat_spent,) = conn.execute(
                f"SELECT COALESCE(SUM(amount_minor), 0) FROM gw_ledger WHERE mandate_id = ? "
                f"AND category = ? AND category_window = ? AND {active}",
                (mandate_id, r.category, r.category_window)).fetchone()
            if cat_spent + r.amount_minor > r.category_max_minor:
                raise LedgerRejection(
                    "category_cap_exceeded",
                    f"{r.category} cap {r.category_max_minor / 100:,.2f}: spent {cat_spent / 100:,.2f}, "
                    f"this payment {r.amount_minor / 100:,.2f}", "padala.category_cap")

            entry_id = conn.execute(
                "INSERT INTO gw_ledger (mandate_id, transaction_id, period, category, category_window, "
                "amount_minor, image_sha256, phash, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (mandate_id, transaction_id, r.period, r.category, r.category_window, r.amount_minor,
                 image_sha256, phash, "reserved", now())).lastrowid
        return entry_id, {
            "budget_spent_before": spent, "budget_minor": r.budget_minor,
            "category_spent_before": cat_spent, "category_max_minor": r.category_max_minor,
            "payments_this_month_before": count,
        }

    def settle(self, entry_id: int) -> None:
        self.db.run("UPDATE gw_ledger SET status = 'settled' WHERE id = ? AND status = 'reserved'", entry_id)

    def release(self, entry_id: int) -> None:
        self.db.run("UPDATE gw_ledger SET status = 'released' WHERE id = ? AND status = 'reserved'", entry_id)

    def reverse(self, transaction_id: str) -> None:
        self.db.run("UPDATE gw_ledger SET status = 'released' WHERE transaction_id = ? AND status = 'settled'",
                    transaction_id)

    def spent(self, mandate_id: str, period: str) -> int:
        row = self.db.one(f"SELECT COALESCE(SUM(amount_minor), 0) AS s FROM gw_ledger WHERE mandate_id = ? "
                          f"AND period = ? AND {ACTIVE}", mandate_id, period)
        return row["s"]

    def category_spent(self, mandate_id: str, category: str, window: str) -> int:
        row = self.db.one(f"SELECT COALESCE(SUM(amount_minor), 0) AS s FROM gw_ledger WHERE mandate_id = ? "
                          f"AND category = ? AND category_window = ? AND {ACTIVE}",
                          mandate_id, category, window)
        return row["s"]


def category_window(cap: dict, execution_date: str) -> str:
    if cap.get("period") == "WINDOW":
        return f"W:{cap['not_before']}..{cap['not_after']}"
    return f"M:{execution_date[:7]}"
