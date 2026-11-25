"""Input validation, link defanging, log masking and per-session rate limiting."""
from __future__ import annotations

import logging
import re
import time
import unicodedata
from collections import deque
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import config

CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class InputError(ValueError):
    """Friendly validation error shown to the user."""


def clean_input(text: str | None) -> str:
    text = unicodedata.normalize("NFC", text or "")
    text = CONTROL.sub("", text).strip()
    if not text:
        raise InputError("Please paste a message first.")
    if len(text) > config.MAX_MESSAGE_CHARS:
        raise InputError(f"The message is too long ({len(text)} characters). "
                         f"Please paste at most {config.MAX_MESSAGE_CHARS} characters.")
    return text


_URL = re.compile(r"(?i)\b(https?)://")
_DOMAIN = re.compile(r"(?i)(?<![@\w])([a-z0-9-]+(?:\.[a-z0-9-]+)*)\.(com|in|net|org|co|app|xyz|info|link|test|ly|top|site|online|gl|cc|id|at|gd|me)\b")


def defang(text: str) -> str:
    """Make links non-clickable for display: https://a.com -> hxxps://a[.]com"""
    text = _URL.sub(lambda m: m.group(1).replace("tt", "xx").replace("TT", "XX") + "://", text)
    return _DOMAIN.sub(lambda m: f"{m.group(1)}[.]{m.group(2)}", text)


_PHONE = re.compile(r"(?<!\d)(\+?91[\s-]?)?([6-9]\d{1})\d{6}(\d{2})(?!\d)")
_LONGNUM = re.compile(r"\b\d{4,}\b")
_EMAIL = re.compile(r"\b([\w.])[\w.]*@([\w-]+\.[\w.]+)\b")


def mask(text: str) -> str:
    """Hide phone numbers, emails and any number with 4+ digits (OTPs, accounts, cards) for logs."""
    text = _PHONE.sub(lambda m: f"{m.group(2)}XXXXXX{m.group(3)}", text)
    text = _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)
    return _LONGNUM.sub("####", text)


class RateLimiter:
    """Sliding-window limiter. Store one per browser session."""

    def __init__(self, limit: int, window_s: int = config.RATE_WINDOW_SECONDS, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window_s, clock
        self.calls: deque[float] = deque()

    def allow(self) -> bool:
        now = self.clock()
        while self.calls and now - self.calls[0] > self.window:
            self.calls.popleft()
        if len(self.calls) >= self.limit:
            return False
        self.calls.append(now)
        return True

    def wait_seconds(self) -> int:
        if not self.calls:
            return 0
        return max(0, int(self.window - (self.clock() - self.calls[0])) + 1)


def get_logger() -> logging.Logger:
    """Logs only metadata (verdict, score, language, length, latency) - never the message itself."""
    log = logging.getLogger("scamshield")
    if not log.handlers:
        path = Path(__file__).resolve().parent.parent / "logs"
        path.mkdir(exist_ok=True)
        h = RotatingFileHandler(path / "scamshield.log", maxBytes=500_000, backupCount=2, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(h)
        log.setLevel(logging.INFO)
    return log
