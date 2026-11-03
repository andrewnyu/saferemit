"""PayPal REST client for the sandbox (and, unchanged, live) APIs.

Endpoints used, with request shapes taken from PayPal's published OpenAPI specs
(github.com/paypal/paypal-rest-api-specifications):

  POST /v1/oauth2/token                    client-credentials access token (cached)
  POST /v3/vault/setup-tokens              start vaulting the OFW's PayPal wallet
  POST /v3/vault/payment-tokens            exchange the approved setup token for a vault id
  POST /v2/checkout/orders                 charge the vaulted wallet, buyer not present
  POST /v2/checkout/orders/{id}/capture    only if the order was not completed on create
  POST /v1/payments/payouts                pay the payee in PHP
  POST /v2/payments/captures/{id}/refund   undo the charge if the payout fails

Every POST carries a `PayPal-Request-Id` so retries are idempotent.
"""

from __future__ import annotations

import time
from decimal import Decimal

import httpx

SANDBOX_BASE = "https://api-m.sandbox.paypal.com"


class PayPalError(Exception):
    def __init__(self, status: int, name: str, message: str, debug_id: str | None = None):
        super().__init__(f"PayPal {status} {name}: {message}" + (f" (debug_id {debug_id})" if debug_id else ""))
        self.status, self.name, self.debug_id = status, name, debug_id


def money(value: Decimal) -> str:
    return f"{value.quantize(Decimal('0.01'))}"


class PayPalREST:
    mode = "sandbox"

    def __init__(self, client_id: str, client_secret: str, base_url: str = SANDBOX_BASE,
                 http: httpx.Client | None = None):
        if not client_id or not client_secret:
            raise ValueError("PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET are required in sandbox mode")
        self.client_id, self.client_secret, self.base_url = client_id, client_secret, base_url
        self.http = http or httpx.Client(timeout=30)
        self._token: str | None = None
        self._token_expires = 0.0

    # ------------------------------------------------------------------ plumbing

    def access_token(self) -> str:
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        response = self.http.post(f"{self.base_url}/v1/oauth2/token",
                                  auth=(self.client_id, self.client_secret),
                                  data={"grant_type": "client_credentials"},
                                  headers={"Accept": "application/json"})
        self._raise_for(response)
        body = response.json()
        self._token, self._token_expires = body["access_token"], time.time() + int(body.get("expires_in", 300))
        return self._token

    def _post(self, path: str, json: dict | None, request_id: str) -> dict:
        headers = {
            "Authorization": f"Bearer {self.access_token()}",
            "Content-Type": "application/json",
            "PayPal-Request-Id": request_id,
            "Prefer": "return=representation",
        }
        response = self.http.post(f"{self.base_url}{path}", json=json if json is not None else {}, headers=headers)
        self._raise_for(response)
        return response.json() if response.content else {}

    @staticmethod
    def _raise_for(response: httpx.Response) -> None:
        if response.status_code < 400:
            return
        try:
            body = response.json()
        except ValueError:
            body = {}
        raise PayPalError(response.status_code, body.get("name") or body.get("error", "ERROR"),
                          body.get("message") or body.get("error_description") or response.text[:200],
                          body.get("debug_id"))

    # ------------------------------------------------------------------ vault (Payment Method Tokens v3)

    def create_setup_token(self, *, return_url: str, cancel_url: str, request_id: str) -> dict:
        body = {
            "payment_source": {
                "paypal": {
                    "description": "Padala: pay my family's bills under rules I sign",
                    "usage_type": "MERCHANT",
                    "customer_type": "CONSUMER",
                    "permit_multiple_payment_tokens": False,
                    "experience_context": {
                        "brand_name": "Padala",
                        "locale": "en-US",
                        "shipping_preference": "NO_SHIPPING",
                        "return_url": return_url,
                        "cancel_url": cancel_url,
                    },
                }
            }
        }
        result = self._post("/v3/vault/setup-tokens", body, request_id)
        approve = next((link["href"] for link in result.get("links", []) if link.get("rel") == "approve"), None)
        return {"id": result["id"], "status": result.get("status"), "approve_url": approve}

    def create_payment_token(self, *, setup_token_id: str, request_id: str) -> dict:
        body = {"payment_source": {"token": {"id": setup_token_id, "type": "SETUP_TOKEN"}}}
        result = self._post("/v3/vault/payment-tokens", body, request_id)
        paypal = (result.get("payment_source") or {}).get("paypal") or {}
        return {"vault_id": result["id"], "customer_id": (result.get("customer") or {}).get("id"),
                "payer_email": paypal.get("email_address")}

    # ------------------------------------------------------------------ charging the vaulted wallet

    def charge_vaulted_wallet(self, *, vault_id: str, usd: Decimal, invoice_id: str, description: str,
                              custom_id: str, request_id: str) -> dict:
        body = {
            "intent": "CAPTURE",
            "purchase_units": [{
                "invoice_id": invoice_id[:127],
                "custom_id": custom_id[:127],
                "description": description[:127],
                "amount": {"currency_code": "USD", "value": money(usd)},
            }],
            "payment_source": {
                "paypal": {
                    "vault_id": vault_id,
                    # Merchant-initiated charge on a saved wallet, buyer not present.
                    "stored_credential": {"payment_initiator": "MERCHANT", "usage": "SUBSEQUENT",
                                          "usage_pattern": "UNSCHEDULED_PREPAID"},
                }
            },
        }
        order = self._post("/v2/checkout/orders", body, request_id)
        if order.get("status") != "COMPLETED":
            order = self._post(f"/v2/checkout/orders/{order['id']}/capture", None, request_id + "-capture")
        capture = order["purchase_units"][0]["payments"]["captures"][0]
        if capture.get("status") not in ("COMPLETED", "PENDING"):
            raise PayPalError(422, "CAPTURE_NOT_COMPLETED", f"capture status {capture.get('status')}")
        return {"order_id": order["id"], "capture_id": capture["id"], "status": capture["status"]}

    def refund_capture(self, *, capture_id: str, request_id: str) -> dict:
        return self._post(f"/v2/payments/captures/{capture_id}/refund", None, request_id)

    # ------------------------------------------------------------------ payouts

    def payout(self, *, receiver_email: str, php: Decimal, note: str, sender_batch_id: str,
               sender_item_id: str, request_id: str) -> dict:
        body = {
            "sender_batch_header": {
                "sender_batch_id": sender_batch_id,
                "recipient_type": "EMAIL",
                "email_subject": "Bayad mula sa Padala",
                "email_message": note[:1000],
            },
            "items": [{
                "recipient_type": "EMAIL",
                "receiver": receiver_email,
                "amount": {"value": money(php), "currency": "PHP"},
                "note": note[:4000],
                "sender_item_id": sender_item_id,
            }],
        }
        result = self._post("/v1/payments/payouts", body, request_id)
        header = result.get("batch_header", {})
        return {"batch_id": header.get("payout_batch_id"), "status": header.get("batch_status")}
