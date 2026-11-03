"""PAYPAL_MODE=mock: a stand-in with the same interface as PayPalREST.

No network, no money, and every id it returns starts with "MOCK-" so nothing in
the UI or a receipt can be mistaken for a real PayPal transaction. Ids are
derived from the PayPal-Request-Id, so the mock is idempotent the same way the
real API is.
"""

from __future__ import annotations

import hashlib
from decimal import Decimal


def _id(prefix: str, seed: str, length: int = 17) -> str:
    return f"MOCK-{prefix}-" + hashlib.sha256(seed.encode()).hexdigest()[:length].upper()


class MockPayPal:
    mode = "mock"

    def __init__(self, base_url: str = "http://localhost:8000", fail_payouts_to: set[str] | None = None):
        self.base_url = base_url.rstrip("/")
        self.fail_payouts_to = fail_payouts_to or set()
        self.calls: list[tuple[str, dict]] = []

    def create_setup_token(self, *, return_url: str, cancel_url: str, request_id: str) -> dict:
        token = _id("SETUP", request_id)
        self.calls.append(("setup_token", {"return_url": return_url}))
        return {"id": token, "status": "PAYER_ACTION_REQUIRED",
                # Relative on purpose: the simulated approval page is served by this app.
                "approve_url": f"/ofw/vault/mock-approve?token={token}"}

    def create_payment_token(self, *, setup_token_id: str, request_id: str) -> dict:
        self.calls.append(("payment_token", {"setup_token_id": setup_token_id}))
        return {"vault_id": _id("VAULT", setup_token_id, 12), "customer_id": _id("CUST", setup_token_id, 10),
                "payer_email": "ofw.sandbox.buyer@example.com"}

    def charge_vaulted_wallet(self, *, vault_id: str, usd: Decimal, invoice_id: str, description: str,
                              custom_id: str, request_id: str) -> dict:
        self.calls.append(("charge", {"vault_id": vault_id, "usd": str(usd)}))
        return {"order_id": _id("ORDER", request_id), "capture_id": _id("CAPTURE", request_id), "status": "COMPLETED"}

    def refund_capture(self, *, capture_id: str, request_id: str) -> dict:
        self.calls.append(("refund", {"capture_id": capture_id}))
        return {"id": _id("REFUND", request_id), "status": "COMPLETED"}

    def payout(self, *, receiver_email: str, php: Decimal, note: str, sender_batch_id: str,
               sender_item_id: str, request_id: str) -> dict:
        from .client import PayPalError

        self.calls.append(("payout", {"receiver": receiver_email, "php": str(php)}))
        if receiver_email in self.fail_payouts_to:
            raise PayPalError(422, "RECEIVER_UNREGISTERED", "mock: receiver cannot accept payouts")
        return {"batch_id": _id("BATCH", sender_batch_id, 13), "status": "PENDING"}
