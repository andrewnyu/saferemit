import json
from decimal import Decimal

import httpx
import pytest

from padala.db import Database
from padala.gateway.verifier import SettlementRequest
from padala.paypal.client import PayPalError, PayPalREST
from padala.paypal.fx import FxProvider
from padala.paypal.mock import MockPayPal
from padala.paypal.settlement import PayPalSettler, php_to_usd


class FakePayPal:
    """httpx transport that records requests and answers like the sandbox."""

    def __init__(self, order_status="COMPLETED", payout_fails=False):
        self.requests = []
        self.order_status = order_status
        self.payout_fails = payout_fails

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content and request.headers.get(
            "content-type", "").startswith("application/json") else None
        self.requests.append((request.method, request.url.path, dict(request.headers), body))
        path = request.url.path
        if path == "/v1/oauth2/token":
            return httpx.Response(200, json={"access_token": "A21AA-test", "expires_in": 32400})
        if path == "/v3/vault/setup-tokens":
            return httpx.Response(201, json={"id": "5C991763VB2781612", "status": "PAYER_ACTION_REQUIRED", "links": [
                {"href": "https://www.sandbox.paypal.com/agreements/approve?approval_session_id=X", "rel": "approve"}]})
        if path == "/v3/vault/payment-tokens":
            return httpx.Response(201, json={"id": "8kk8451t", "customer": {"id": "customer_4029352050"},
                                             "payment_source": {"paypal": {"email_address": "buyer@example.com"}}})
        if path == "/v2/checkout/orders":
            pu = {"payments": {"captures": [{"id": "3C679366HH908993F", "status": "COMPLETED"}]}}
            if self.order_status != "COMPLETED":
                pu = {}
            return httpx.Response(201, json={"id": "5O190127TN364715T", "status": self.order_status,
                                             "purchase_units": [pu]})
        if path.endswith("/capture"):
            return httpx.Response(201, json={"id": "5O190127TN364715T", "status": "COMPLETED", "purchase_units": [
                {"payments": {"captures": [{"id": "CAPTURED-LATER", "status": "COMPLETED"}]}}]})
        if path == "/v1/payments/payouts":
            if self.payout_fails:
                return httpx.Response(422, json={"name": "RECEIVER_UNREGISTERED", "message": "nope", "debug_id": "d1"})
            return httpx.Response(201, json={"batch_header": {"payout_batch_id": "5UXD2E8A7EBQJ", "batch_status": "PENDING"}})
        if path.endswith("/refund"):
            return httpx.Response(201, json={"id": "1JU08902781691411", "status": "COMPLETED"})
        return httpx.Response(404, json={"name": "NOT_FOUND"})


def client(fake):
    return PayPalREST("id", "secret", http=httpx.Client(transport=httpx.MockTransport(fake)))


def test_vault_onboarding_shapes():
    fake = FakePayPal()
    pp = client(fake)
    setup = pp.create_setup_token(return_url="https://x/return", cancel_url="https://x/cancel", request_id="r1")
    assert setup["approve_url"].startswith("https://www.sandbox.paypal.com/")
    token = pp.create_payment_token(setup_token_id=setup["id"], request_id="r2")
    assert token == {"vault_id": "8kk8451t", "customer_id": "customer_4029352050", "payer_email": "buyer@example.com"}

    _, _, headers, body = fake.requests[1]
    wallet = body["payment_source"]["paypal"]
    assert wallet["usage_type"] == "MERCHANT" and wallet["experience_context"]["return_url"] == "https://x/return"
    assert headers["paypal-request-id"] == "r1" and headers["authorization"] == "Bearer A21AA-test"
    assert fake.requests[2][3] == {"payment_source": {"token": {"id": "5C991763VB2781612", "type": "SETUP_TOKEN"}}}
    # The OAuth token is fetched once and cached.
    assert sum(1 for r in fake.requests if r[1] == "/v1/oauth2/token") == 1


def test_charge_vaulted_wallet_and_payout_shapes():
    fake = FakePayPal()
    pp = client(fake)
    charge = pp.charge_vaulted_wallet(vault_id="8kk8451t", usd=Decimal("76.25"), invoice_id="inv",
                                      description="d", custom_id="c", request_id="r3")
    assert charge["capture_id"] == "3C679366HH908993F"
    order = next(r for r in fake.requests if r[1] == "/v2/checkout/orders")[3]
    assert order["intent"] == "CAPTURE"
    assert order["payment_source"]["paypal"]["vault_id"] == "8kk8451t"
    assert order["purchase_units"][0]["amount"] == {"currency_code": "USD", "value": "76.25"}

    payout = pp.payout(receiver_email="school@example.com", php=Decimal("4460.35"), note="n",
                       sender_batch_id="b1", sender_item_id="i1", request_id="r4")
    assert payout == {"batch_id": "5UXD2E8A7EBQJ", "status": "PENDING"}
    item = next(r for r in fake.requests if r[1] == "/v1/payments/payouts")[3]["items"][0]
    assert item["amount"] == {"value": "4460.35", "currency": "PHP"} and item["recipient_type"] == "EMAIL"


def test_order_not_completed_is_captured():
    fake = FakePayPal(order_status="APPROVED")
    charge = client(fake).charge_vaulted_wallet(vault_id="v", usd=Decimal("1"), invoice_id="i", description="d",
                                                custom_id="c", request_id="r")
    assert charge["capture_id"] == "CAPTURED-LATER"


def test_paypal_error_carries_debug_id():
    with pytest.raises(PayPalError, match="debug_id d1"):
        client(FakePayPal(payout_fails=True)).payout(receiver_email="x", php=Decimal("1"), note="n",
                                                     sender_batch_id="b", sender_item_id="i", request_id="r")


def test_settlement_refunds_when_payout_fails(tmp_path):
    fake = FakePayPal(payout_fails=True)
    fx = FxProvider(Database(tmp_path / "db.sqlite3"), offline=True, fallback_rate=58.5)
    settle = PayPalSettler(client(fake), fx, vault_id=lambda: "8kk8451t")
    result = settle(SettlementRequest("tx1", {"paypal_email": "p@example.com", "name": "P"}, 4_460_35, "PHP", "ref", "memo"))
    assert not result.ok and "capture refunded" in result.error
    assert any(r[1].endswith("/refund") for r in fake.requests)


def test_settlement_idempotency_keys_are_stable(tmp_path):
    fake = FakePayPal()
    fx = FxProvider(Database(tmp_path / "db.sqlite3"), offline=True, fallback_rate=58.5)
    settle = PayPalSettler(client(fake), fx, vault_id=lambda: "v")
    req = SettlementRequest("tx-same", {"paypal_email": "p@example.com", "name": "P"}, 100_00, "PHP", "ref", "memo")
    settle(req)
    settle(req)
    ids = [r[2]["paypal-request-id"] for r in fake.requests if r[1] == "/v2/checkout/orders"]
    assert len(ids) == 2 and ids[0] == ids[1]


def test_fx_rounding_and_fallback(tmp_path):
    assert php_to_usd(Decimal("4460.35"), Decimal("58.50")) == Decimal("76.25")  # rounded up
    fx = FxProvider(Database(tmp_path / "db.sqlite3"), offline=False, fallback_rate=58.5,
                    http=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503))))
    rate, source = fx.usd_php()
    assert rate == Decimal("58.5") and "fallback" in source
    ok = FxProvider(Database(tmp_path / "db2.sqlite3"), offline=False, fallback_rate=58.5,
                    http=httpx.Client(transport=httpx.MockTransport(
                        lambda r: httpx.Response(200, json={"date": "2026-11-02", "rates": {"PHP": 57.91}}))))
    assert ok.usd_php() == (Decimal("57.91"), "frankfurter.app 2026-11-02")


def test_mock_is_labelled():
    mock = MockPayPal()
    assert mock.charge_vaulted_wallet(vault_id="v", usd=Decimal(1), invoice_id="i", description="d", custom_id="c",
                                      request_id="r")["capture_id"].startswith("MOCK-")
