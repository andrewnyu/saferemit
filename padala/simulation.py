"""Software stand-ins used ONLY by tests, seed scripts and scripts/redteam.py.

In the real app the OFW's key is a non-extractable WebCrypto key in the browser.
Here a Python key plays that role so the full flow can run headless.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from padala.config import Settings
from padala.crypto import jws
from padala.crypto.jwk import generate_private_key, public_jwk, thumbprint
from padala.gateway.verifier import STEP_UP_TYP
from padala.intake.extract import ExtractionResult, load_fixtures
from padala.intake.schema import BillExtraction
from padala.mandates import model as m
from padala.mandates import open_mandate
from padala.paypal.mock import MockPayPal
from padala.services import Services, seed_registry

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


class SoftwareDevice:
    """Plays the OFW's browser: holds a P-256 key and signs what it is shown."""

    def __init__(self):
        self.key = generate_private_key()
        self.jwk = public_jwk(self.key)
        self.kid = thumbprint(self.jwk)

    def sign_draft(self, draft: open_mandate.Draft) -> str:
        return jws.sign(draft.header, draft.payload, self.key).rsplit(".", 1)[1]

    def decide(self, closed_content: dict, decision: str, bill_id: int | None = None,
               iat: int | None = None) -> str:
        payload = {"vct": m.STEP_UP_VCT, "decision": decision, "closed_mandate": closed_content,
                   "bill_id": bill_id, "iat": iat or int(time.time())}
        return jws.sign({"typ": STEP_UP_TYP, "kid": self.kid}, payload, self.key)


def make_settings(data_dir: Path) -> Settings:
    return Settings(data_dir=Path(data_dir), base_url="http://testserver", paypal_mode="mock",
                    paypal_client_id="", paypal_client_secret="", intake_mode="offline",
                    anthropic_api_key="", fx_offline=True, fx_fallback_rate=58.50)


def build_world(data_dir: Path, clock: Callable[[], float] = time.time,
                paypal: MockPayPal | None = None) -> tuple[Services, SoftwareDevice]:
    services = Services(make_settings(data_dir), paypal_client=paypal or MockPayPal("http://testserver"), clock=clock)
    seed_registry(services)
    device = SoftwareDevice()
    services.register_device_key(device.jwk, "software device (tests only)")
    services.start_vault()
    services.complete_vault()
    return services, device


def sign_plan(services: Services, device: SoftwareDevice, plan: m.Plan | None = None) -> str:
    plan_id, draft = services.create_draft(plan or services.default_plan())
    return services.activate_plan(plan_id, device.sign_draft(draft))


def sample(key: str) -> bytes:
    return (SAMPLES / f"{key}.png").read_bytes()


def submit_sample(services: Services, key: str, by: str = "Mama Rosario") -> int:
    return services.agent.submit_bill(sample(key), filename=f"{key}.png", mime="image/png", submitted_by=by)


def fooled_reading_of_injection() -> ExtractionResult:
    """What a compromised model would return for the injection bill: it obeys the
    text, names the attacker's payee and reports nothing suspicious."""
    fixture = next(f for f in load_fixtures().values() if f["key"] == "prompt-injection")
    fooled = {**fixture["extraction"], "biller_name": "BSA Accounting Office (new account)",
              "tampering_signals": [], "embedded_instructions": []}
    return ExtractionResult(BillExtraction.model_validate(fooled), "offline-fixture",
                            "Simulated compromised extraction: no AI call was made")
