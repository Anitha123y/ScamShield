"""Detect the language / script mix of a message (no internet needed)."""
from __future__ import annotations

import re
from dataclasses import dataclass

DEVANAGARI = re.compile(r"[ऀ-ॿ]")
TELUGU = re.compile(r"[ఀ-౿]")
LATIN_WORD = re.compile(r"[a-z]{2,}")
URL = re.compile(r"(https?://\S+|www\.\S+|\S+\.(?:com|in|net|org|test|ly|app)\S*)")
# Short tech words that appear in every language and should not count as "English".
SHARED = {"otp", "kyc", "upi", "pin", "atm", "sms", "sbi", "hdfc", "icici", "pan", "id", "ok", "rs", "inr",
          "app", "link", "bank", "account", "aadhaar", "sim", "pm", "am"}

HINGLISH = {
    "hai", "hain", "aap", "aapka", "aapke", "aapki", "apna", "apne", "karo", "karein", "kare", "karna", "kar",
    "ke", "ki", "ka", "ko", "nahi", "nahin", "mat", "ho", "hoga", "jayega", "jaayega", "jaega", "raha", "rahe",
    "rahi", "bhejo", "bhej", "paise", "paisa", "abhi", "turant", "jaldi", "kya", "se", "mein", "liye", "bhai",
    "yeh", "ye", "woh", "milega", "kijiye", "dijiye", "batao", "bataye", "bataiye", "band", "ghante", "aaj",
    "kal", "sakte", "sakta", "chahiye", "wala", "wale", "hua", "hui", "gaya", "gayi", "par", "pe", "lekin",
    "aur", "bhi", "sirf", "kisi", "kabhi", "beta", "mummy", "papa", "ji", "haan", "accha", "theek",
}
TENGLISH = {
    "meeru", "mee", "meeku", "miku", "cheyandi", "cheyyandi", "cheyakandi", "ledu", "undi", "unnayi",
    "avutundi", "avtundi", "ivvandi", "pampandi", "cheppandi", "cheppakandi", "kosam", "ante", "kani", "andi",
    "garu", "emaina", "ippudu", "ventane", "vaddu", "chesi", "chestham", "ostundi", "vastundi", "kadu", "ela",
    "enti", "nenu", "naku", "naaku", "mana", "meeku", "ayindi", "chesukondi", "chudandi", "raandi", "randi",
    "babu", "amma", "nanna", "ee", "roju", "gantallo", "dabbulu", "dabbu", "pampu", "cheyi",
}


@dataclass
class LanguageInfo:
    label: str   # English, Hindi, Telugu, Hinglish, Hindi-English, Telugu-English
    script: str  # Latin, Devanagari, Telugu, Mixed


def detect_language(text: str) -> LanguageInfo:
    t = URL.sub(" ", text.lower())
    deva = len(DEVANAGARI.findall(t))
    telu = len(TELUGU.findall(t))
    words = [w for w in LATIN_WORD.findall(t) if w not in SHARED]

    if deva or telu:
        native = "Hindi" if deva >= telu else "Telugu"
        script = "Devanagari" if native == "Hindi" else "Telugu"
        if len(words) >= 3:
            return LanguageInfo(f"{native}-English", "Mixed")
        return LanguageInfo(native, script)

    if not words:
        return LanguageInfo("English", "Latin")
    hi = sum(w in HINGLISH for w in words)
    te = sum(w in TENGLISH for w in words)
    if te >= 2 and te >= hi:
        return LanguageInfo("Telugu-English", "Latin")
    if hi >= 2 and hi / len(words) >= 0.15:
        return LanguageInfo("Hinglish", "Latin")
    return LanguageInfo("English", "Latin")
