"""USD -> PHP rate from frankfurter.app (ECB reference rates), cached.

The rate used for every payment is recorded on its receipt and payment row.
If frankfurter.app is unreachable we use the last cached rate, and failing
that a configured fallback rate, and say so in `source`.
"""

from __future__ import annotations

import time
from decimal import Decimal

import httpx

from padala.db import Database

FRANKFURTER_URL = "https://api.frankfurter.dev/v1/latest"
CACHE_KEY = "fx:USD:PHP"
TTL_SECONDS = 6 * 3600


class FxProvider:
    def __init__(self, db: Database, *, offline: bool, fallback_rate: float, http: httpx.Client | None = None):
        self.db, self.offline, self.fallback = db, offline, Decimal(str(fallback_rate))
        self.http = http

    def usd_php(self) -> tuple[Decimal, str]:
        cached = self.db.kv_get(CACHE_KEY)
        if cached and time.time() - cached["fetched_at"] < TTL_SECONDS:
            return Decimal(cached["rate"]), f"frankfurter.app {cached['date']} (cached)"
        if not self.offline:
            try:
                http = self.http or httpx.Client(timeout=5)
                response = http.get(FRANKFURTER_URL, params={"from": "USD", "to": "PHP"})
                response.raise_for_status()
                body = response.json()
                rate = Decimal(str(body["rates"]["PHP"]))
                self.db.kv_set(CACHE_KEY, {"rate": str(rate), "date": body.get("date"), "fetched_at": time.time()})
                return rate, f"frankfurter.app {body.get('date')}"
            except (httpx.HTTPError, KeyError, ValueError):
                pass
        if cached:
            return Decimal(cached["rate"]), f"frankfurter.app {cached['date']} (stale cache)"
        return self.fallback, "fallback rate (frankfurter.app unavailable)"
