"""PayPal integration: REST client (sandbox), clearly-labelled mock, FX and settlement."""

from padala.config import Settings

from .client import PayPalError, PayPalREST
from .mock import MockPayPal


def make_client(settings: Settings):
    if settings.paypal_mode == "sandbox":
        return PayPalREST(settings.paypal_client_id, settings.paypal_client_secret)
    return MockPayPal(base_url=settings.base_url)


__all__ = ["MockPayPal", "PayPalError", "PayPalREST", "make_client"]
