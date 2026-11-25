"""ScamShield web server (FastAPI).

Run:   python -m uvicorn web.server:app --port 8000      (from the project folder, or double-click run_app.bat)
Docs:  http://localhost:8000/docs   (automatic API documentation)

The server does two jobs:
  1. Serves the website (web/static/index.html, style.css, app.js).
  2. Offers a REST API that the website calls:
       GET  /api/config   -> settings for the page (is AI available? demo messages)
       POST /api/check    -> fast scam check (~1 second, no AI)
       POST /api/explain  -> optional Gemini explanation / second opinion (10-40 seconds)
The scam-detection logic itself lives in the engine/ folder - this file only connects it to the web.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from engine import analyze, config
from engine.detector import Result
from engine.gemini import GeminiError, explain, fallback_explanation, merge, second_opinion
from engine.security import InputError, RateLimiter, clean_input, defang, get_logger

app = FastAPI(title="ScamShield API", version="3.1",
              description="Scam detection for Indian SMS / WhatsApp messages (English, Hindi, Telugu, Hinglish).")
STATIC = Path(__file__).resolve().parent / "static"   # web/static, works from any working folder
app.mount("/static", StaticFiles(directory=STATIC), name="static")
log = get_logger()

LANGUAGES = ["English", "Hindi", "Telugu", "Tamil", "Kannada", "Marathi", "Bengali"]
DEMOS = {
    "🏦 KYC block": "Dear customer your SBI account will be blocked today. Update KYC now: http://sbi-kyc-verify.example.test",
    "💼 Part-time job": "Earn Rs 5000 daily from home by liking YouTube videos. Pay Rs 499 registration fee. WhatsApp 9876501234",
    "💸 UPI 'receive'": "You have received Rs 2,000 cashback. Scan the QR and enter your UPI PIN to receive it.",
    "🗣️ Hinglish": "Aapka SIM 2 ghante mein band ho jayega. KYC ke liye turant OTP bhejo.",
    "తెలుగు": "మీ బ్యాంక్ ఖాతా బ్లాక్ అవుతుంది. వెంటనే OTP చెప్పండి.",
    "📱 New number": "Hi, I changed my number. Please save this contact. Can you do me a small favour?",
    "✅ Bank alert": "Rs 450 debited from A/c XX1234 for Swiggy order. Avl bal Rs 9,870. Not you? Call the number on the back of your card.",
    "✅ OTP warning": "Your OTP for login is 482913. Do not share this OTP with anyone.",
}
TITLE = {"SCAM": "This looks like a SCAM", "SUSPICIOUS": "SUSPICIOUS – verify first", "SAFE": "Looks SAFE"}
MEANING = {
    "HIGH": "Strong scam evidence. Do not reply, click, pay or share anything.",
    "MEDIUM": "Could be genuine, but check through the official app or a number you already know.",
    "LOW": "No strong scam signs found. Still, never share OTP, PIN or passwords.",
}


# ---------- request bodies (Pydantic checks the type and size automatically) ----------
class CheckRequest(BaseModel):
    message: str = Field(..., max_length=config.MAX_MESSAGE_CHARS)


class ExplainRequest(CheckRequest):
    language: str = "English"
    second_opinion: bool = False


# ---------- security helpers ----------
check_limits: dict[str, RateLimiter] = {}   # one limiter per visitor IP address
ai_limits: dict[str, RateLimiter] = {}


def rate_limit(request: Request, table: dict, limit: int) -> None:
    ip = request.client.host if request.client else "unknown"
    limiter = table.setdefault(ip, RateLimiter(limit))
    if not limiter.allow():
        raise HTTPException(429, f"Too many requests. Please wait {limiter.wait_seconds()} seconds.")


def validated(message: str) -> str:
    try:
        return clean_input(message)
    except InputError as e:
        raise HTTPException(400, str(e)) from None


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Extra browser protections. CSP = the page may only load scripts/styles from this server."""
    response = await call_next(request)
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi")):
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; object-src 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# ---------- turning an engine Result into JSON for the browser ----------
def finding_json(f) -> dict:
    return {"name": f.name, "why": f.why, "evidence": defang(f.evidence), "critical": f.critical}


def segments(text: str, r: Result) -> list[dict]:
    """Split the message into pieces so the page can highlight risky words.
    Links are 'defanged' (http -> hxxp) so nothing in the message is clickable."""
    kinds = {"red": "red", "verify": "verify", "good": "good"}
    spans = sorted(((f.span[0], f.span[1], kinds[f.kind], f.name) for f in r.red + r.verify + r.good if f.span),
                   key=lambda s: (s[0], -s[1]))
    out, pos = [], 0
    for start, end, kind, name in spans:
        if start < pos:               # overlapping highlight -> skip
            continue
        if start > pos:
            out.append({"text": defang(text[pos:start]), "kind": None})
        out.append({"text": defang(text[start:end]), "kind": kind, "label": name})
        pos = end
    if pos < len(text):
        out.append({"text": defang(text[pos:]), "kind": None})
    return out


def explanation_json(ex, source: str) -> dict:
    return {"source": source, "summary": ex.summary,
            "reasons": [{"point": p, "quote": defang(q)} for p, q in ex.reasons],
            "what_to_do": ex.what_to_do,
            "model": ex.telemetry.model, "latency_ms": ex.telemetry.latency_ms}


def result_json(text: str, r: Result, verdict: str | None = None) -> dict:
    verdict = verdict or r.verdict
    return {
        "verdict": verdict, "title": TITLE[verdict], "risk_level": r.risk_level, "meaning": MEANING[r.risk_level],
        "score": round(r.score, 4), "language": r.language.label,
        "red": [finding_json(f) for f in r.red], "verify": [finding_json(f) for f in r.verify],
        "good": [finding_json(f) for f in r.good], "context": [name for name, _ in r.context],
        "segments": segments(text, r), "breakdown": r.breakdown,
        "explanation": explanation_json(fallback_explanation(r), "rules"),
    }


# ---------- pages ----------
@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC / "index.html")


# ---------- API ----------
@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/config")
def get_config():
    """Tells the page whether AI is available. The API key itself NEVER leaves the server."""
    return {"ai_available": bool(os.getenv("GEMINI_API_KEY")), "languages": LANGUAGES,
            "demos": DEMOS, "max_chars": config.MAX_MESSAGE_CHARS}


@app.post("/api/check")
def check(body: CheckRequest, request: Request):
    """Fast check: ML model + rules. No AI, so hidden instructions in the message cannot change the verdict."""
    rate_limit(request, check_limits, config.CHECKS_PER_WINDOW)
    text = validated(body.message)
    t0 = time.monotonic()
    r = analyze(text)
    log.info("check verdict=%s score=%.2f lang=%s len=%d ms=%d", r.verdict, r.score, r.language.label,
             len(text), int((time.monotonic() - t0) * 1000))      # metadata only - never the message
    return result_json(text, r)


@app.post("/api/explain")
def ai_explain(body: ExplainRequest, request: Request):
    """Optional Gemini step. Runs AFTER /api/check, so the user already sees the result while waiting.
    Gemini may only RAISE the risk (second opinion); it can never make a scam look safe."""
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        raise HTTPException(503, "AI is not set up on this server.")
    if body.language not in LANGUAGES:
        raise HTTPException(400, "Unsupported language.")
    rate_limit(request, ai_limits, config.AI_CALLS_PER_WINDOW)
    text = validated(body.message)
    r = analyze(text)                      # re-run the fast engine: the API keeps no memory between requests
    final, note, opinion = r.verdict, None, None
    try:
        if body.second_opinion:
            op = second_opinion(text, api_key=key)
            final, note = merge(r, op)
            opinion = {"label": op.label, "confidence": op.confidence,
                       "manipulation_attempt": op.manipulation_attempt}
        ex = explain(text, r, body.language, api_key=key)
    except GeminiError as e:
        raise HTTPException(502, str(e)) from None
    log.info("explain lang=%s second=%s final=%s ms=%s", body.language, body.second_opinion, final,
             ex.telemetry.latency_ms)
    return {"verdict": final, "title": TITLE[final], "merge_note": note, "second_opinion": opinion,
            "explanation": explanation_json(ex, "ai")}
