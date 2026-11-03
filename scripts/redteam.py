"""Red team: try to make the gateway move money it should not.

    python scripts/redteam.py

Each scenario builds a fresh world (temporary database, mock PayPal, a software
stand-in for the OFW's device key, the default plan), plays an attack, and
checks the gateway refused it with the expected error at the expected step.
Exit code 1 if any attack got through.
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from padala.crypto import sdjwt  # noqa: E402
from padala.crypto.jwk import generate_private_key  # noqa: E402
from padala.evidence import dhash, sha256_hex, to_minor  # noqa: E402
from padala.gateway import GatewayResult, Presentation  # noqa: E402
from padala.intake.extract import extract_offline  # noqa: E402
from padala.mandates import closed_mandate as cm  # noqa: E402
from padala.mandates import open_mandate  # noqa: E402
from padala.simulation import SoftwareDevice, build_world, sample, sign_plan, submit_sample  # noqa: E402

DEMO_NOW = 1_793_671_200  # 2026-11-03 10:00 Asia/Manila


class Clock:
    def __init__(self, t: int = DEMO_NOW):
        self.t = t

    def __call__(self) -> int:
        return self.t


def world(budget_minor: int | None = None):
    clock = Clock()
    time.time = clock  # the fake clock drives db timestamps and nonce TTLs too
    services, device = build_world(Path(tempfile.mkdtemp(prefix="padala-redteam-")), clock=clock)
    plan = services.default_plan()
    if budget_minor is not None:
        plan.monthly_budget_minor = budget_minor
    sign_plan(services, device, plan)
    return services, device, clock


def craft(services, key: str, *, agent_key=None, payee_patch: dict | None = None) -> tuple[Presentation, dict]:
    """Do what the agent does for a sample bill, but by hand so we can tamper."""
    data = sample(key)
    image_sha = sha256_hex(data)
    path = services.settings.uploads_dir / f"{image_sha}.png"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    services.gateway.register_evidence(image_sha, str(path), "image/png", dhash(data))
    extraction = extract_offline(image_sha).extraction.model_dump()
    signer = agent_key or services.agent_key
    evidence = cm.evidence_jwt(signer, image_sha256=image_sha, phash=dhash(data), extraction=extraction,
                               extraction_source="offline-fixture", iat=services.clock())
    open_token = sdjwt.parse(services.active_plan()["sd_jwt"])
    payee = next(d.value for d in open_token.decoded_disclosures()
                 if isinstance(d.value, dict) and d.value.get("name") == extraction["biller_name"])
    payee = {**payee, **(payee_patch or {})}
    content = cm.closed_mandate_content(transaction_id=cm.transaction_id_for(evidence), payee=payee,
                                        amount_minor=to_minor(extraction["amount_due"]), currency="PHP",
                                        execution_date="2026-11-03")
    gw = services.gateway
    p = cm.build_presentation(open_token=open_token, agent_key=signer, content=content, aud=gw.audience,
                              nonce=gw.issue_nonce(), iat=services.clock(),
                              prev_receipt=gw.latest_receipt(services.active_plan()["mandate_id"]))
    return Presentation(p.chain, evidence), content


# --------------------------------------------------------------------------- scenarios


def tampered_amount() -> GatewayResult:
    """Agent edits the amount inside the closed mandate after signing it."""
    services, _, _ = world()
    p, _ = craft(services, "negros-power")
    open_seg, closed_seg = sdjwt.split_chain(p.chain)
    content = sdjwt.parse_disclosure(closed_seg.disclosures[0])
    forged_value = json.loads(json.dumps(content.value))
    forged_value["payment_amount"]["amount"] = 44_603_50  # 10x
    forged = sdjwt.make_disclosure(forged_value, salt=content.salt)
    closed_seg.disclosures[0] = forged.encoded
    return services.gateway.process(Presentation(sdjwt.join_chain([open_seg, closed_seg]), p.evidence_jwt))


def tampered_budget() -> GatewayResult:
    """Someone edits the OFW-signed open mandate to raise the budget."""
    services, _, _ = world()
    p, _ = craft(services, "negros-power")
    open_seg, closed_seg = sdjwt.split_chain(p.chain)
    for i, enc in enumerate(open_seg.disclosures):
        d = sdjwt.parse_disclosure(enc)
        if isinstance(d.value, dict) and "constraints" in d.value:
            value = json.loads(json.dumps(d.value))
            for c in value["constraints"]:
                if c["type"] == "payment.budget":
                    c["max"] = 999_999.0
            open_seg.disclosures[i] = sdjwt.make_disclosure(value, salt=d.salt).encoded
    return services.gateway.process(Presentation(sdjwt.join_chain([open_seg, closed_seg]), p.evidence_jwt))


def payee_not_allowed() -> GatewayResult:
    """A cousin uploads a doctored bill from a clinic the OFW never approved."""
    services, _, _ = world()
    bill_id = submit_sample(services, "hospital-doctored", by="Cousin Jun")
    return _result_for(services, bill_id)


def replay() -> GatewayResult:
    """Re-send a presentation the gateway already accepted and paid."""
    services, _, _ = world()
    p, _ = craft(services, "negros-power")
    first = services.gateway.process(p)
    assert first.paid, first.trace
    return services.gateway.process(p)


def replay_fresh_nonce() -> GatewayResult:
    """Re-sign the same paid transaction with a fresh nonce (a buggy or greedy agent)."""
    services, _, _ = world()
    p, content = craft(services, "negros-power")
    assert services.gateway.process(p).paid
    gw = services.gateway
    again = cm.build_presentation(open_token=sdjwt.parse(services.active_plan()["sd_jwt"]),
                                  agent_key=services.agent_key, content=content, aud=gw.audience,
                                  nonce=gw.issue_nonce(), iat=services.clock(),
                                  prev_receipt=gw.latest_receipt(services.active_plan()["mandate_id"]))
    return gw.process(Presentation(again.chain, p.evidence_jwt))


def wrong_agent_key() -> GatewayResult:
    """A different agent (not the key in the OFW's cnf) signs a closed mandate."""
    services, _, _ = world()
    p, _ = craft(services, "negros-power", agent_key=generate_private_key())
    return services.gateway.process(p)


def forged_device_key() -> GatewayResult:
    """An attacker signs their own 'open mandate' with an unregistered key."""
    services, _, _ = world()
    attacker = SoftwareDevice()
    plan = services.default_plan()
    plan.monthly_budget_minor = 10_000_000_00
    draft = open_mandate.prepare(plan, services.agent_jwk, attacker.kid, services.clock())
    services.db.run("UPDATE plans SET sd_jwt = ? WHERE status = 'active'",
                    open_mandate.sign_with_software_key(draft, attacker.key).serialize())
    p, _ = craft(services, "negros-power")
    return services.gateway.process(p)


def over_budget() -> GatewayResult:
    """Monthly budget ₱15,000: power (₱4,460.35) is paid, tuition (₱14,250) would exceed it."""
    services, _, _ = world(budget_minor=15_000_00)
    first = _result_for(services, submit_sample(services, "negros-power"))
    assert first.paid, first.trace
    return _result_for(services, submit_sample(services, "tuition"))


def expired_mandate() -> GatewayResult:
    """The agent keeps using the open mandate after its short exp (31 days later)."""
    services, _, clock = world()
    clock.t += 31 * 86_400
    time.time = clock
    p, _ = craft(services, "negros-power")
    return services.gateway.process(p)


def prompt_injection_new_payee() -> GatewayResult:
    """The bill tells the AI to pay a 'new account'; a fooled agent drafts exactly that."""
    services, _, _ = world()
    return _result_for(services, submit_sample(services, "prompt-injection"))


def prompt_injection_swap_email() -> GatewayResult:
    """A smarter injection: keep the school's name, swap in the attacker's PayPal email."""
    services, _, _ = world()
    p, _ = craft(services, "tuition", payee_patch={"paypal_email": "bsa.accounting.payments@gmail.example"})
    return services.gateway.process(p)


def _result_for(services, bill_id: int) -> GatewayResult:
    row = services.db.one("SELECT receipt_id FROM bills WHERE id = ?", bill_id)
    receipt = services.receipt(row["receipt_id"])
    payload = receipt["payload"]
    return GatewayResult(outcome="paid" if payload["status"] == "Success" else "rejected",
                         receipt_id=receipt["id"], receipt_jwt=receipt["receipt_jwt"], receipt=payload,
                         trace=receipt["trace"], error=payload.get("error"),
                         error_description=payload.get("error_description"))


@dataclass
class Scenario:
    name: str
    run: Callable[[], GatewayResult]
    expected_error: str
    expected_step: str


SCENARIOS = [
    Scenario("tampered amount", tampered_amount, "bad_closed_mandate", "closed_content"),
    Scenario("tampered budget (open mandate)", tampered_budget, "bad_disclosure", "open_disclosures"),
    Scenario("payee not allowed (doctored clinic bill)", payee_not_allowed, "payee_not_allowed", "c:payment.allowed_payees"),
    Scenario("replay of a paid presentation", replay, "replay", "key_binding"),
    Scenario("replay with a fresh nonce", replay_fresh_nonce, "replay", "ledger"),
    Scenario("wrong agent key", wrong_agent_key, "bad_agent_signature", "key_binding"),
    Scenario("forged OFW device key", forged_device_key, "unknown_device_key", "issuer_signature"),
    Scenario("over budget", over_budget, "over_budget", "ledger"),
    Scenario("expired mandate", expired_mandate, "mandate_expired", "open_validity"),
    Scenario("prompt injection: pay a new payee", prompt_injection_new_payee, "payee_not_allowed", "c:payment.allowed_payees"),
    Scenario("prompt injection: swap payee email", prompt_injection_swap_email, "payee_not_allowed", "c:payment.allowed_payees"),
]


def run_all(verbose: bool = True) -> list[dict]:
    real_time = time.time
    rows = []
    try:
        for sc in SCENARIOS:
            result = sc.run()
            failed = next((s for s in result.trace if s["result"] == "fail"), None)
            blocked = not result.paid
            ok = blocked and result.error == sc.expected_error and failed and failed["step"] == sc.expected_step
            rows.append({"scenario": sc.name, "blocked": blocked, "error": result.error,
                         "step": failed["step"] if failed else None,
                         "detail": failed["detail"] if failed else result.error_description, "ok": bool(ok)})
            time.time = real_time
    finally:
        time.time = real_time
    if verbose:
        width = max(len(r["scenario"]) for r in rows)
        print(f"{'scenario':<{width}}  result   error / failing step")
        print("-" * (width + 60))
        for r in rows:
            mark = "BLOCKED" if r["ok"] else ("blocked?" if r["blocked"] else "PAID!!")
            print(f"{r['scenario']:<{width}}  {mark:<8} {r['error']} @ {r['step']}")
            print(f"{'':<{width}}           {r['detail']}")
        print("-" * (width + 60))
        print(f"{sum(r['ok'] for r in rows)}/{len(rows)} attacks blocked at the expected step")
    return rows


if __name__ == "__main__":
    results = run_all()
    sys.exit(0 if all(r["ok"] for r in results) else 1)
