import io
import json

import anthropic
import httpx
import httpx2
import pytest
from PIL import Image

from loopremit.evidence import sha256_hex
from loopremit.intake import extract
from loopremit.intake.checks import run_checks, seasonal_anomaly
from loopremit.simulation import sample

PAYEES = json.loads(open("samples/payees.json").read())["payees"]


def _png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (40, 40), "white").save(buf, "PNG")
    return buf.getvalue()


def _anthropic(monkeypatch, response_json):
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        seen["beta"] = request.headers.get("anthropic-beta")
        return httpx2.Response(200, json=response_json)

    real = anthropic.Anthropic
    monkeypatch.setattr(anthropic, "Anthropic", lambda **kw: real(
        api_key="test", http_client=httpx2.Client(transport=httpx2.MockTransport(handler))))
    return seen


def _message(stop_reason, text="", stop_details=None):
    return {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
            "content": [{"type": "text", "text": text}] if text else [], "stop_reason": stop_reason,
            "stop_sequence": None, "stop_details": stop_details, "usage": {"input_tokens": 1, "output_tokens": 1}}


def test_anthropic_request_and_parse(monkeypatch):
    fixture = next(iter(extract.load_fixtures().values()))["extraction"]
    seen = _anthropic(monkeypatch, _message("end_turn", json.dumps(fixture)))
    result = extract.extract_with_anthropic(_png(), "test")
    assert result.extraction.biller_name == fixture["biller_name"]
    assert result.source == "ai:claude-opus-5-5"
    body = seen["body"]
    assert body["model"] == "claude-opus-5-5" and body["fallbacks"] == "default"
    assert body["output_config"]["format"]["type"] == "json_schema"
    assert body["messages"][0]["content"][0]["type"] == "image"
    assert "server-side-fallback-2026-07-01" in seen["beta"]
    assert "untrusted" in body["system"]


def test_anthropic_refusal_is_handled(monkeypatch):
    _anthropic(monkeypatch, _message("refusal", stop_details={"type": "refusal", "category": "cyber",
                                                           "explanation": "declined"}))
    with pytest.raises(extract.IntakeRefused) as info:
        extract.extract_with_anthropic(_png(), "test")
    assert info.value.category == "cyber"


def test_anthropic_max_tokens_is_an_error(monkeypatch):
    _anthropic(monkeypatch, _message("max_tokens", '{"biller_name": "trunc'))
    with pytest.raises(extract.IntakeError):
        extract.extract_with_anthropic(_png(), "test")


def test_offline_fixture_only_for_known_images():
    result = extract.extract_offline(sha256_hex(sample("tuition")))
    assert result.source == "offline-fixture" and "no AI call" in result.label
    with pytest.raises(extract.IntakeError):
        extract.extract_offline(sha256_hex(b"some other image"))


def test_seasonal_anomaly_power_bill():
    history = next(p for p in PAYEES if p["id"] == "negros-power")["history"]
    a = seasonal_anomaly(4_460_35, "2026-10", history)
    assert a["pct_vs_last_year"] == 62 and a["flag"]
    normal = seasonal_anomaly(2_800_00, "2026-10", history)
    assert not normal["flag"]
    # A summer-sized bill in May is normal for May.
    assert not seasonal_anomaly(3_700_00, "2026-05", history)["flag"]


def test_checks_flag_doctored_bill():
    fixture = next(f for f in extract.load_fixtures().values() if f["key"] == "hospital-doctored")
    payees = [{**p, "aliases": p.get("aliases", [])} for p in PAYEES]
    payee, checks, _ = run_checks(fixture["extraction"], payees=payees, history={}, period="2026-10",
                                  phash="0" * 64, prior_bills=[])
    results = {c.name: c.result for c in checks}
    assert payee is None and results["payee_registry"] == "fail" and results["line_items_sum"] == "fail"
    assert results["tampering"] == "warn"


def _openrouter(reply=None, status=200):
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(status, json=reply if reply is not None else {})

    return seen, httpx.Client(transport=httpx.MockTransport(handler))


def _openrouter_reply(content, finish="stop", **message):
    return {"model": "anthropic/claude-opus-5.5",
            "choices": [{"finish_reason": finish, "message": {"role": "assistant", "content": content, **message}}]}


def test_openrouter_request_and_parse():
    fixture = next(iter(extract.load_fixtures().values()))["extraction"]
    seen, http = _openrouter(_openrouter_reply(json.dumps(fixture)))
    result = extract.extract_with_openrouter(_png(), "sk-test", http=http)
    assert result.extraction.biller_name == fixture["biller_name"]
    assert result.source == "ai:anthropic/claude-opus-5.5" and result.label == "Read by the AI model"
    body = seen["body"]
    assert seen["auth"] == "Bearer sk-test" and body["provider"]["require_parameters"] is True
    assert "untrusted" in body["messages"][0]["content"]
    assert body["messages"][1]["content"][0]["image_url"]["url"].startswith("data:image/jpeg;base64,")
    schema = body["response_format"]["json_schema"]
    assert schema["strict"] is True and schema["schema"]["additionalProperties"] is False
    assert schema["schema"]["$defs"]["LineItem"]["additionalProperties"] is False


@pytest.mark.parametrize("reply, status, error", [
    ({}, 401, extract.IntakeError),
    ({}, 402, extract.IntakeError),
    ({"error": {"message": "upstream down"}}, 200, extract.IntakeError),
    ({"choices": []}, 200, extract.IntakeError),
    (_openrouter_reply('{"biller_name": "trunc', finish="length"), 200, extract.IntakeError),
    (_openrouter_reply('{"biller_name": "no other fields"}'), 200, extract.IntakeError),
    (_openrouter_reply("", refusal="declined"), 200, extract.IntakeRefused),
])
def test_openrouter_bad_replies_go_to_a_human(reply, status, error):
    _, http = _openrouter(reply, status)
    with pytest.raises(error):
        extract.extract_with_openrouter(_png(), "sk-test", http=http)
