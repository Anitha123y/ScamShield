"""Clean up messy messages so rules can match them: spelling, abbreviations, phones, currency."""
from __future__ import annotations

import re
import unicodedata

ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿]")

# Common informal spellings / abbreviations -> standard word (applied to whole words only).
WORD_FIXES = {
    "pls": "please", "plz": "please", "plse": "please", "plss": "please",
    "ur": "your", "u": "you", "r": "are",
    "acc": "account", "acct": "account", "accnt": "account", "acount": "account", "accont": "account",
    "a/c": "account", "ac": "account",
    "immediatly": "immediately", "imediately": "immediately", "immediatley": "immediately", "immedietly": "immediately",
    "urgnt": "urgent", "urjent": "urgent", "argent": "urgent",
    "verfy": "verify", "verifiy": "verify", "vrfy": "verify",
    "recieve": "receive", "recive": "receive", "recevie": "receive",
    "pymt": "payment", "pmt": "payment", "paymnt": "payment",
    "blcked": "blocked", "blokd": "blocked", "blockd": "blocked",
    "suspnded": "suspended", "deactivate": "deactivated",
    "kyc.": "kyc", "e-kyc": "ekyc", "re-kyc": "kyc",
    "0tp": "otp", "o.t.p": "otp", "o.t.p.": "otp",
    "k.y.c": "kyc", "k.y.c.": "kyc",
    "msg": "message", "txn": "transaction", "amt": "amount", "bal": "balance",
    "govt": "government", "sarkari": "government",
}

_word_re = re.compile(r"(?<![\w/.])(" + "|".join(re.escape(k) for k in sorted(WORD_FIXES, key=len, reverse=True)) + r")(?![\w/])")

# Indian mobile numbers in many formats -> 10 digits.  +91 98765 43210 / 098765-43210 / 98765.43210
_phone_re = re.compile(r"(?<!\d)(?:\+?\s?91[\s.-]?|0)?([6-9]\d{4})[\s.-]?(\d{5})(?!\d)")
# Toll-free 1800-xxx-xxxx -> 1800xxxxxxx
_tollfree_re = re.compile(r"(?<!\d)(1800)[\s.-]?(\d{3})[\s.-]?(\d{3,4})(?!\d)")
# Currency: ₹5,000 / Rs.5000 / INR 5k / 5000rs / Rs 1.5 lakh -> "rs 5000"
_num_commas = re.compile(r"(?<=\d),(?=\d)")
_cur_before = re.compile(r"(?:₹|\brs\.?|\binr)\s*(\d[\d.]*\d|\d)(?:\s*(k|lakhs|lakh|lac|crore|cr)\b)?")
_cur_after = re.compile(r"\b(\d[\d.]*\d|\d)(?:\s*(k|lakhs|lakh|lac|crore|cr))?\s*(?:rs\.?|rupees|inr|/-)(?!\w)")
_MULT = {"k": 1_000, "lakh": 100_000, "lac": 100_000, "lakhs": 100_000, "cr": 10_000_000, "crore": 10_000_000}


def _amount(num: str, unit: str | None) -> str:
    try:
        value = float(num.rstrip("."))
    except ValueError:
        return num
    if unit:
        value *= _MULT[unit]
    return str(int(value)) if value == int(value) else str(value)


def normalize(text: str) -> str:
    """Return a lower-cased, cleaned copy of the message used for rule matching."""
    t = unicodedata.normalize("NFKC", text)
    t = ZERO_WIDTH.sub("", t)
    t = t.lower()
    t = _num_commas.sub("", t)
    t = _phone_re.sub(lambda m: m.group(1) + m.group(2), t)
    t = _tollfree_re.sub(lambda m: "".join(m.groups()), t)
    t = _cur_before.sub(lambda m: f"rs {_amount(m.group(1), m.group(2))}", t)
    t = _cur_after.sub(lambda m: f"rs {_amount(m.group(1), m.group(2))}", t)
    t = _word_re.sub(lambda m: WORD_FIXES[m.group(1)], t)
    t = re.sub(r"[ \t]+", " ", t)
    return t.strip()
