from fastapi.testclient import TestClient

from loopremit.crypto import jws
from loopremit.paypal.mock import MockPayPal
from loopremit.services import Services
from loopremit.simulation import SoftwareDevice, make_settings
from loopremit.web.app import create_app


def test_web_demo_flow(tmp_path, clock, monkeypatch):
    import time

    monkeypatch.setattr(time, "time", clock)
    services = Services(make_settings(tmp_path), paypal_client=MockPayPal(), clock=clock)
    client = TestClient(create_app(services))
    device = SoftwareDevice()  # plays the browser's WebCrypto key

    kid = client.post("/api/ofw/device-key", json={"jwk": device.jwk}).json()["kid"]
    assert kid == device.kid
    assert client.post("/api/ofw/device-key", json={"jwk": {**device.jwk, "d": "x"}}).status_code == 400

    approve = client.post("/ofw/vault/start", follow_redirects=False).headers["location"]
    assert approve.startswith("/ofw/vault/mock-approve")
    token = approve.split("token=")[1]
    assert client.get(f"/ofw/vault/return?approval_token_id={token}", follow_redirects=False).status_code == 303
    assert services.vault()["vault_id"].startswith("MOCK-VAULT-")

    plan = services.default_plan()
    form = {"payees": [p.id for p in plan.payees], "monthly_budget": "40000", "max_payments": "12",
            "amount_min": "100", "amount_max": "30000", "step_up_over": "15000", "valid_days": "30",
            "not_before": plan.not_before, "not_after": plan.not_after, "kid": kid,
            "caps": [{"category": c.category, "max": str(c.max_minor / 100), "period": c.period,
                      "not_before": c.not_before, "not_after": c.not_after, "label": c.label} for c in plan.caps]}
    draft = client.post("/api/ofw/plan/draft", json=form).json()
    signing_input = draft["draft"]["signing_input"]
    signature = jws.sign(draft["draft"]["header"], draft["draft"]["payload"], device.key).rsplit(".", 1)[1]
    # A signature over anything else is refused.
    bad = jws.sign({"alg": "ES256"}, {"x": 1}, device.key).rsplit(".", 1)[1]
    assert client.post(f"/api/ofw/plan/{draft['plan_id']}/sign", json={"signature": bad}).status_code == 400
    assert jws.signing_input(draft["draft"]["header"], draft["draft"]["payload"]) == signing_input
    assert client.post(f"/api/ofw/plan/{draft['plan_id']}/sign", json={"signature": signature}).status_code == 200

    r = client.post("/family/samples/negros-power", data={"submitted_by": "Mama"}, follow_redirects=False)
    bill_url = r.headers["location"]
    assert "Paid" in client.get(bill_url).text
    bill_id = int(bill_url.rsplit("/", 1)[1])
    detail = client.get(f"/ofw/bills/{bill_id}").text
    assert "Gateway verification" in detail and "MOCK-CAPTURE-" in detail

    for url in ["/", "/ofw", "/ofw/plan", "/ofw/approvals", "/ofw/onboarding", "/family",
                f"/bills/{bill_id}/image", "/.well-known/loopremit-gateway.json"]:
        assert client.get(url).status_code == 200, url
    assert client.post("/family/bills", files={"file": ("x.txt", b"hello", "text/plain")}).status_code == 400
