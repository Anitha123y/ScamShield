"""ScamShield classification engine: ML model + weighted rules + context. No AI/LLM involved,
so text inside a message can never "instruct" the classifier."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import joblib

from . import config
from .language import LanguageInfo, detect_language
from .normalize import normalize
from .rules import CONTEXT_COMBOS, Finding, find

MODEL_PATH = Path(__file__).resolve().parent.parent / "data" / "model" / "scam_model.joblib"
_model = None


def get_model():
    global _model
    if _model is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError("Model not found. Run: python scripts/train.py")
        _model = joblib.load(MODEL_PATH)
    return _model


@dataclass
class Result:
    verdict: str                  # SCAM | SUSPICIOUS | SAFE
    risk_level: str               # HIGH | MEDIUM | LOW
    score: float                  # final risk score 0..1
    model_probability: float      # raw ML model output 0..1
    language: LanguageInfo
    red: list[Finding] = field(default_factory=list)
    verify: list[Finding] = field(default_factory=list)
    good: list[Finding] = field(default_factory=list)
    context: list[tuple[str, float]] = field(default_factory=list)
    breakdown: list[str] = field(default_factory=list)
    normalized_text: str = ""

    # --- backwards-compatible names used by older code ---
    @property
    def scam_probability(self) -> float:
        return self.score

    @property
    def red_flags(self) -> list[tuple[str, str]]:
        return [(f.name, f.why) for f in self.red]

    @property
    def suspicious_signs(self) -> list[tuple[str, str]]:
        return [(f.name, f.why) for f in self.verify]

    @property
    def safe_signs(self) -> list[str]:
        return [f.name for f in self.good]

    @property
    def has_critical(self) -> bool:
        return any(f.critical for f in self.red)


def _noisy_or(weights) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - w
    return 1.0 - p


def verdict_for(score: float) -> tuple[str, str]:
    if score >= config.SCAM_THRESHOLD:
        return "SCAM", "HIGH"
    if score >= config.SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS", "MEDIUM"
    return "SAFE", "LOW"


def analyze(text: str) -> Result:
    text = (text or "").strip()
    if not text:
        raise ValueError("Message is empty")

    lang = detect_language(text)
    norm = normalize(text)
    findings = find(text, norm)
    red = [f for f in findings if f.kind == "red"]
    verify = [f for f in findings if f.kind == "verify"]
    good = [f for f in findings if f.kind == "good"]
    breakdown: list[str] = []

    # 1) ML model, trusted according to language (it learned English SMS).
    model_p = float(get_model().predict_proba([text])[0][1])
    trust = config.ML_TRUST.get(lang.label, config.ML_TRUST_DEFAULT)
    ml_part = model_p * trust
    breakdown.append(f"ML model says {model_p:.0%}; trusted {trust:.0%} for {lang.label} -> {ml_part:.0%}")

    # 2) Weighted red flags + context combinations.
    tags = set().union(*(f.tags for f in red)) if red else set()
    context = [(name, w) for need, w, name in CONTEXT_COMBOS if need <= tags]
    red_evidence = _noisy_or([f.weight for f in red] + [w for _, w in context])
    for f in red:
        breakdown.append(f"+ {f.name} (weight {f.weight:.2f}{', CRITICAL' if f.critical else ''})")
    for name, w in context:
        breakdown.append(f"+ Context: {name} (weight {w:.2f})")

    score = 1.0 - (1.0 - ml_part) * (1.0 - red_evidence)
    critical = any(f.critical for f in red)
    if critical and score < config.CRITICAL_MIN_SCORE:
        score = config.CRITICAL_MIN_SCORE
        breakdown.append(f"Critical red flag -> score raised to at least {config.CRITICAL_MIN_SCORE:.0%}")

    # 3) Good signs lower the score - but never cancel strong or critical evidence.
    if good:
        if critical or red_evidence >= config.STRONG_EVIDENCE:
            breakdown.append("Good signs ignored: the scam evidence is too strong")
        else:
            factor = 1.0 - _noisy_or([g.weight for g in good])
            score *= factor
            breakdown.append(f"- Good signs ({', '.join(g.name for g in good)}) -> score x{factor:.2f}")

    # 4) Things to verify: not a scam on their own, but should not be called SAFE.
    if verify and not good and score < config.VERIFY_FLOOR:
        score = config.VERIFY_FLOOR
        breakdown.append(f"Things to verify found -> at least {config.VERIFY_FLOOR:.0%} (Suspicious)")

    score = max(0.0, min(1.0, score))
    verdict, level = verdict_for(score)
    breakdown.append(f"= Final risk {score:.0%} -> {verdict} ({level} risk)")
    return Result(verdict, level, score, model_p, lang, red, verify, good, context, breakdown, norm)
