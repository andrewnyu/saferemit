"""SQLite storage. One file, plain SQL, no ORM.

Tables prefixed `gw_` belong to the gateway (the deterministic verifier). The
rest is application state for the OFW/family app and the bill agent.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);

-- OFW device keys registered at onboarding (public JWK only; the private key
-- never leaves the browser).
CREATE TABLE IF NOT EXISTS device_keys (
    kid TEXT PRIMARY KEY, jwk TEXT NOT NULL, label TEXT,
    created_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS vault (
    id INTEGER PRIMARY KEY, mode TEXT NOT NULL, status TEXT NOT NULL,
    setup_token_id TEXT, vault_id TEXT, customer_id TEXT, payer_email TEXT,
    created_at INTEGER NOT NULL);

-- Known payees (sandbox: PayPal business accounts) and their bill history.
CREATE TABLE IF NOT EXISTS payees (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL,
    account_number TEXT NOT NULL, paypal_email TEXT NOT NULL,
    website TEXT, aliases TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS bill_history (
    payee_id TEXT NOT NULL, period TEXT NOT NULL, amount_minor INTEGER NOT NULL,
    PRIMARY KEY (payee_id, period));

-- Remittance plans = open Payment Mandates.
CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY, status TEXT NOT NULL, settings TEXT NOT NULL,
    draft TEXT, sd_jwt TEXT, kid TEXT, mandate_id TEXT,
    created_at INTEGER NOT NULL, signed_at INTEGER, exp INTEGER);

CREATE TABLE IF NOT EXISTS bills (
    id INTEGER PRIMARY KEY, submitted_by TEXT NOT NULL, filename TEXT,
    mime TEXT, image_sha256 TEXT NOT NULL, phash TEXT,
    status TEXT NOT NULL, status_detail TEXT,
    extraction TEXT, extraction_source TEXT, checks TEXT,
    evidence_jwt TEXT, transaction_id TEXT, closed_content TEXT,
    receipt_id TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);

-- Things only the OFW can decide: step-up approvals and escalations.
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY, bill_id INTEGER NOT NULL, kind TEXT NOT NULL,
    status TEXT NOT NULL, reason TEXT, payload TEXT, decision_jws TEXT,
    created_at INTEGER NOT NULL, decided_at INTEGER);

CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY, bill_id INTEGER NOT NULL, receipt_id TEXT,
    php_minor INTEGER NOT NULL, usd_cents INTEGER, fx_rate TEXT, fx_source TEXT,
    order_id TEXT, capture_id TEXT, payout_batch_id TEXT, payout_status TEXT,
    paypal_mode TEXT, status TEXT NOT NULL, error TEXT, created_at INTEGER NOT NULL);

-- Gateway state.
CREATE TABLE IF NOT EXISTS gw_nonces (
    nonce TEXT PRIMARY KEY, issued_at INTEGER NOT NULL, used_at INTEGER);
CREATE TABLE IF NOT EXISTS gw_ledger (
    id INTEGER PRIMARY KEY, mandate_id TEXT NOT NULL, transaction_id TEXT NOT NULL,
    period TEXT NOT NULL, category TEXT NOT NULL, category_window TEXT NOT NULL,
    amount_minor INTEGER NOT NULL, image_sha256 TEXT NOT NULL, phash TEXT NOT NULL,
    status TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS gw_ledger_mandate ON gw_ledger (mandate_id, status);
CREATE TABLE IF NOT EXISTS gw_receipts (
    id TEXT PRIMARY KEY, mandate_id TEXT, transaction_id TEXT, bill_id INTEGER,
    status TEXT NOT NULL, error TEXT, receipt_jwt TEXT NOT NULL, trace TEXT NOT NULL,
    presentation TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS gw_evidence (
    image_sha256 TEXT PRIMARY KEY, phash TEXT NOT NULL, path TEXT NOT NULL,
    mime TEXT, created_at INTEGER NOT NULL);
"""


class Database:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        # isolation_level=None: we issue BEGIN ourselves where atomicity matters.
        conn = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        """BEGIN IMMEDIATE takes the write lock up front, so two concurrent
        ledger reservations cannot both read the same remaining budget."""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            try:
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    # Small helpers keep call sites short and readable.
    def one(self, sql: str, *args: Any) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(sql, args).fetchone()

    def all(self, sql: str, *args: Any) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(sql, args).fetchall()

    def run(self, sql: str, *args: Any) -> int:
        with self.connect() as conn:
            return conn.execute(sql, args).lastrowid

    def kv_get(self, key: str, default: Any = None) -> Any:
        row = self.one("SELECT value FROM kv WHERE key = ?", key)
        return json.loads(row["value"]) if row else default

    def kv_set(self, key: str, value: Any) -> None:
        self.run("INSERT INTO kv (key, value) VALUES (?, ?) "
                 "ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, json.dumps(value))


def now() -> int:
    return int(time.time())
