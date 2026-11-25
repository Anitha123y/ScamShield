"""API tests using FastAPI's TestClient (no real server or internet needed)."""
import pytest
from fastapi.testclient import TestClient

from web import server


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    server.check_limits.clear()
    server.ai_limits.clear()
    return TestClient(server.app)


def test_home_page_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "ScamShield" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_config_never_exposes_key(client, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "SECRET-KEY-123")
    r = client.get("/api/config").json()
    assert r["ai_available"] is True
    assert "SECRET-KEY-123" not in str(r)


def test_check_scam(client):
    r = client.post("/api/check", json={"message": "Your SBI account will be blocked today. Update KYC at http://sbi-kyc.example.test"})
    body = r.json()
    assert r.status_code == 200 and body["verdict"] == "SCAM" and body["risk_level"] == "HIGH"
    assert body["red"] and all("evidence" in f for f in body["red"])
    # links are defanged everywhere so nothing is clickable
    assert "http://" not in str(body["segments"]) and "hxxp://" in str(body["segments"])
    assert body["explanation"]["source"] == "rules"


def test_check_safe(client):
    body = client.post("/api/check", json={"message": "Your OTP is 482913. Do not share this OTP with anyone."}).json()
    assert body["verdict"] == "SAFE" and body["good"]


def test_segments_rebuild_original_message(client):
    msg = "Hello! Please share the OTP now."
    segs = client.post("/api/check", json={"message": msg}).json()["segments"]
    assert "".join(s["text"] for s in segs) == msg
    assert any(s["kind"] == "red" for s in segs)


def test_html_in_message_is_just_data(client):
    msg = "<script>alert(1)</script> win a prize now"
    r = client.post("/api/check", json={"message": msg})
    assert r.status_code == 200   # accepted as text; the page shows it with textContent, never runs it


@pytest.mark.parametrize("payload,code", [
    ({"message": "   "}, 400),
    ({"message": "x" * 2001}, 422),
    ({}, 422),
    ({"message": 123}, 422),
])
def test_bad_input_rejected(client, payload, code):
    assert client.post("/api/check", json=payload).status_code == code


def test_rate_limit(client):
    for _ in range(server.config.CHECKS_PER_WINDOW):
        assert client.post("/api/check", json={"message": "hello"}).status_code == 200
    r = client.post("/api/check", json={"message": "hello"})
    assert r.status_code == 429 and "wait" in r.json()["detail"]


def test_explain_without_key_is_friendly(client):
    r = client.post("/api/explain", json={"message": "Share your OTP now"})
    assert r.status_code == 503


def test_explain_rejects_unknown_language(client, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    r = client.post("/api/explain", json={"message": "hi", "language": "Klingon"})
    assert r.status_code == 400


def test_explain_with_fake_gemini(client, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    from engine import gemini as g
    fake = g.Explanation("Scam message.", [("Fake link", "hxxp://x")], ["Report at cybercrime.gov.in"],
                         telemetry=g.Telemetry(model="fake", latency_ms=5))
    monkeypatch.setattr(server, "explain", lambda *a, **k: fake)
    r = client.post("/api/explain", json={"message": "Share your OTP now", "language": "Hindi"}).json()
    assert r["verdict"] == "SCAM" and r["explanation"]["source"] == "ai" and r["explanation"]["model"] == "fake"


def test_explain_gemini_failure_is_friendly(client, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    from engine import gemini as g

    def boom(*a, **k):
        raise g.GeminiError("Google's AI is busy right now.")
    monkeypatch.setattr(server, "explain", boom)
    r = client.post("/api/explain", json={"message": "Share your OTP now"})
    assert r.status_code == 502 and "busy" in r.json()["detail"]


def test_api_docs_available(client):
    assert client.get("/docs").status_code == 200
