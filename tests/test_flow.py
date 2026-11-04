import json
import time

from padala.paypal.mock import MockPayPal
from padala.simulation import build_world, fooled_reading_of_injection, sign_plan, submit_sample


def bill(services, bill_id):
    return dict(services.db.one("SELECT * FROM bills WHERE id = ?", bill_id))


def test_tuition_and_power_paid_automatically(planned):
    services, _ = planned
    tuition = submit_sample(services, "tuition")
    power = submit_sample(services, "negros-power")
    for bid in (tuition, power):
        b = bill(services, bid)
        assert b["status"] == "paid", b["status_detail"]
        receipt = services.receipt(b["receipt_id"])
        assert receipt["payload"]["status"] == "Success"
        assert receipt["payload"]["psp_confirmation_id"].startswith("MOCK-CAPTURE-")
        assert all(s["result"] in ("pass",) for s in receipt["trace"]), receipt["trace"]
    checks = json.loads(bill(services, power)["checks"])
    assert checks["anomaly"]["flag"] and checks["anomaly"]["pct_vs_last_year"] == 62

    summary = services.budget_summary()
    assert summary["spent"] == 14_250_00 + 4_460_35
    cats = {c["category"]: c for c in summary["categories"]}
    assert cats["education"]["spent"] == 14_250_00 and cats["utilities"]["spent"] == 4_460_35


def test_doctored_hospital_bill_rejected_and_escalated(planned):
    services, device = planned
    bid = submit_sample(services, "hospital-doctored", by="Cousin Jun")
    b = bill(services, bid)
    assert b["status"] == "rejected"
    receipt = services.receipt(b["receipt_id"])
    assert receipt["payload"]["error"] == "payee_not_allowed"
    failed = {s["step"] for s in receipt["trace"] if s["result"] == "fail"}
    assert "c:payment.allowed_payees" in failed and "c:padala.evidence_required" in failed
    approval = services.db.one("SELECT * FROM approvals WHERE bill_id = ?", bid)
    assert approval["kind"] == "escalation" and approval["status"] == "pending"
    services.agent.decline_escalation(approval["id"], device.decide({}, "decline", bill_id=bid))
    assert bill(services, bid)["status"] == "declined"


def test_fooled_model_cannot_add_payee(planned, monkeypatch):
    services, _ = planned
    monkeypatch.setattr("padala.agent.extract_offline", lambda _sha: fooled_reading_of_injection())
    b = bill(services, submit_sample(services, "prompt-injection"))
    assert b["status"] == "rejected"
    assert services.receipt(b["receipt_id"])["payload"]["error"] == "payee_not_allowed"


def test_flagged_bill_for_a_real_payee_waits_for_the_ofw(planned):
    """Claude's real reading of the injection bill: the school's name, plus warnings."""
    services, device = planned
    bid = submit_sample(services, "prompt-injection")
    b = bill(services, bid)
    assert b["status"] == "awaiting_ofw" and "warnings" in b["status_detail"]
    assert any(c["name"] == "prompt_injection" for c in json.loads(b["checks"])["checks"])
    assert not [c for c in services.paypal.calls if c[0] == "charge"]
    approval = services.db.one("SELECT * FROM approvals WHERE bill_id = ? AND kind = 'step_up'", bid)
    result = services.agent.approve_step_up(
        approval["id"], device.decide(json.loads(approval["payload"]), "decline", bill_id=bid))
    assert result.error == "declined_by_ofw" and bill(services, bid)["status"] == "declined"
    assert not [c for c in services.paypal.calls if c[0] == "charge"]


def test_flagged_bill_pays_only_with_the_ofw_signature(planned):
    services, device = planned
    bid = submit_sample(services, "prompt-injection")
    approval = services.db.one("SELECT * FROM approvals WHERE bill_id = ? AND kind = 'step_up'", bid)
    result = services.agent.approve_step_up(
        approval["id"], device.decide(json.loads(approval["payload"]), "approve", bill_id=bid))
    assert result.paid, result.trace
    assert bill(services, bid)["status"] == "paid"


def test_bill_stays_processing_until_the_payout_is_delivered(tmp_path, clock, monkeypatch):
    monkeypatch.setattr(time, "time", clock)
    services, device = build_world(tmp_path, clock=clock, paypal=MockPayPal(hold_payouts=True))
    sign_plan(services, device)
    bid = submit_sample(services, "negros-power")
    assert bill(services, bid)["status"] == "paying"
    services.paypal.hold_payouts = False
    clock.state["t"] += 10
    services.reconcile_payouts()
    assert bill(services, bid)["status"] == "paid"
    assert services.db.one("SELECT payout_status FROM payments WHERE bill_id = ?", bid)["payout_status"] == "SUCCESS"


def test_returned_payout_refunds_and_gives_the_budget_back(tmp_path, clock, monkeypatch):
    monkeypatch.setattr(time, "time", clock)
    paypal = MockPayPal(return_payouts_to={"negros-power@business.example.com"})
    services, device = build_world(tmp_path, clock=clock, paypal=paypal)
    sign_plan(services, device)
    bid = submit_sample(services, "negros-power")
    b = bill(services, bid)
    assert b["status"] == "failed" and "RETURNED" in b["status_detail"] and "capture refunded" in b["status_detail"]
    assert [c for c in paypal.calls if c[0] == "refund"]
    assert services.budget_summary()["spent"] == 0
    services.reconcile_payouts(bid)  # a second look must not refund twice
    assert len([c for c in paypal.calls if c[0] == "refund"]) == 1


def test_step_up_rent_needs_ofw_signature(planned):
    services, device = planned
    bid = submit_sample(services, "casa-maria-rent")
    b = bill(services, bid)
    assert b["status"] == "awaiting_ofw"
    approval = services.db.one("SELECT * FROM approvals WHERE bill_id = ? AND kind = 'step_up'", bid)
    content = json.loads(approval["payload"])
    result = services.agent.approve_step_up(approval["id"], device.decide(content, "approve", bill_id=bid))
    assert result.paid, result.trace
    assert bill(services, bid)["status"] == "paid"


def test_step_up_decline(planned):
    services, device = planned
    bid = submit_sample(services, "casa-maria-rent")
    approval = services.db.one("SELECT * FROM approvals WHERE bill_id = ? AND kind = 'step_up'", bid)
    result = services.agent.approve_step_up(
        approval["id"], device.decide(json.loads(approval["payload"]), "decline", bill_id=bid))
    assert result.error == "declined_by_ofw"
    assert bill(services, bid)["status"] == "declined"


def test_duplicate_bill_rejected(planned):
    services, _ = planned
    first = submit_sample(services, "negros-power")
    second = submit_sample(services, "negros-power")
    assert bill(services, first)["status"] == "paid"
    b = bill(services, second)
    assert b["status"] == "rejected"
    assert services.receipt(b["receipt_id"])["payload"]["error"] == "duplicate_bill"


def test_bill_before_plan_waits(world):
    services, _ = world
    assert bill(services, submit_sample(services, "tuition"))["status"] == "waiting_for_plan"
