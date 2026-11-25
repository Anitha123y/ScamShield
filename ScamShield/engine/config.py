"""All tunable numbers in one place. Change values here, not inside the code."""

# ---- Verdict thresholds (final risk score 0..1) ----
# Tuned on the 50-message DEVELOPMENT benchmark only (never on the sealed test set).
# Grid search 25-Nov-2026: higher cut-offs (0.85-0.90) scored better on the 50 dev messages but
# turned regression-test scams (e.g. family-emergency money requests) into SUSPICIOUS.
# Rejected as over-fitting a tiny set; 0.65 kept (0 safe->scam, 0 scams downgraded on dev).
SCAM_THRESHOLD = 0.65        # score >= this  -> SCAM       (risk level HIGH)
SUSPICIOUS_THRESHOLD = 0.35  # score >= this  -> SUSPICIOUS (risk level MEDIUM), else SAFE (LOW)

# ---- How much to trust the ML model, per detected language ----
# The ML model was trained on English SMS only, so its opinion on other scripts is weak.
ML_TRUST = {
    "English": 0.85,
    "Hinglish": 0.55,
    "Telugu-English": 0.45,
    "Hindi-English": 0.35,
    "Hindi": 0.15,
    "Telugu": 0.15,
}
ML_TRUST_DEFAULT = 0.5

# ---- Rule combination ----
CRITICAL_MIN_SCORE = 0.85      # a critical red flag (e.g. OTP request) alone gives at least this
STRONG_EVIDENCE = 0.80         # if red-flag evidence >= this, Good Signs can NOT lower the score
VERIFY_FLOOR = 0.45            # "Things to verify" with no Good Signs -> at least SUSPICIOUS

# ---- Input & usage limits ----
MAX_MESSAGE_CHARS = 2000
CHECKS_PER_WINDOW = 20         # message checks allowed per browser session per window
AI_CALLS_PER_WINDOW = 8        # Gemini calls allowed per browser session per window
RATE_WINDOW_SECONDS = 300

# ---- Gemini ----
GEMINI_MODELS = ["gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.5-flash", "gemini-3.1-flash-lite"]
GEMINI_TIMEOUT_MS = 30_000     # per request
GEMINI_TOTAL_BUDGET_S = 75     # give up after this many seconds in total
GEMINI_RETRIES_PER_MODEL = 2   # tries per model for busy / timeout / rate-limit errors
GEMINI_MIN_CONFIDENCE_TO_RAISE = 0.70  # second opinion may raise SAFE -> SUSPICIOUS only above this
