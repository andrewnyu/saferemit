"""Money movement for one verified payment. Only the gateway calls this.

  1. convert PHP -> USD at the recorded rate (rounded up to the cent, so the
     payee is never short),
  2. charge the OFW's vaulted PayPal wallet in USD (Orders v2, vault_id),
  3. pay the payee in PHP (Payouts),
  4. if the payout fails, refund the capture.
"""

from __future__ import annotations

import uuid
from decimal import ROUND_CEILING, Decimal
from typing import Callable

import httpx

from loopremit.gateway.verifier import SettlementRequest, SettlementResult

from .client import PayPalError
from .fx import FxProvider


def php_to_usd(php: Decimal, rate: Decimal) -> Decimal:
    return (php / rate).quantize(Decimal("0.01"), rounding=ROUND_CEILING)


def _request_id(kind: str, transaction_id: str) -> str:
    # Deterministic per payment: a retried settlement reuses the same id and
    # PayPal returns the original result instead of charging twice.
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"loopremit:{kind}:{transaction_id}"))


class PayPalSettler:
    def __init__(self, client, fx: FxProvider, vault_id: Callable[[], str | None]):
        self.client, self.fx, self.vault_id = client, fx, vault_id

    def __call__(self, req: SettlementRequest) -> SettlementResult:
        mode = self.client.mode
        vault_id = self.vault_id()
        if not vault_id:
            return SettlementResult(False, mode, error="no vaulted PayPal wallet: finish OFW onboarding first")
        if req.currency != "PHP":
            return SettlementResult(False, mode, error=f"unsupported payout currency {req.currency}")
        php = Decimal(req.amount_minor) / 100
        rate, source = self.fx.usd_php()
        usd = php_to_usd(php, rate)
        result = SettlementResult(True, mode, usd_cents=int(usd * 100), fx_rate=str(rate), fx_source=source)
        try:
            charge = self.client.charge_vaulted_wallet(
                vault_id=vault_id, usd=usd, invoice_id=f"loopremit-{req.transaction_id[:40]}",
                description=req.memo, custom_id=req.reference[:127], request_id=_request_id("charge", req.transaction_id))
        except PayPalError as exc:
            return SettlementResult(False, mode, error=f"charge failed: {exc}", fx_rate=str(rate), fx_source=source)
        result.order_id, result.capture_id = charge["order_id"], charge["capture_id"]
        try:
            payout = self.client.payout(
                receiver_email=req.payee["paypal_email"], php=php, note=req.memo,
                sender_batch_id=f"loopremit-{req.transaction_id[:24]}", sender_item_id=req.transaction_id[:30],
                request_id=_request_id("payout", req.transaction_id))
        except PayPalError as exc:
            _, note = self.refund(req.transaction_id, charge["capture_id"])
            return SettlementResult(False, mode, order_id=charge["order_id"], capture_id=charge["capture_id"],
                                    error=f"payout failed: {exc}; {note}", fx_rate=str(rate), fx_source=source)
        result.payout_batch_id, result.payout_status = payout["batch_id"], payout["status"]
        return result

    def refund(self, transaction_id: str, capture_id: str) -> tuple[bool, str]:
        """Refund a capture. The request id is stable, so a retry cannot refund twice."""
        try:
            self.client.refund_capture(capture_id=capture_id, request_id=_request_id("refund", transaction_id))
            return True, "capture refunded"
        except (PayPalError, httpx.HTTPError) as exc:
            return False, f"REFUND FAILED, reconcile manually: {exc}"
