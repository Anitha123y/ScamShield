import pytest

from engine import config
from engine.language import detect_language
from engine.normalize import normalize
from engine.security import InputError, RateLimiter, clean_input, defang, mask


@pytest.mark.parametrize("text,label", [
    ("Your parcel is on hold", "English"),
    ("Aapka SIM 2 ghante mein band ho jayega", "Hinglish"),
    ("mee account block avutundi, otp cheppandi", "Telugu-English"),
    ("आपका खाता बंद हो जाएगा OTP भेजें", "Hindi"),
    ("మీ బ్యాంక్ ఖాతా బ్లాక్ అవుతుంది", "Telugu"),
    ("आपका bank account will be blocked today please update", "Hindi-English"),
    ("మీ account will be blocked today please verify now", "Telugu-English"),
])
def test_language_detection(text, label):
    assert detect_language(text).label == label


@pytest.mark.parametrize("raw,expected", [
    ("Pls send ur 0TP immediatly", "please send your otp immediately"),
    ("call +91 98765 43210", "call 9876543210"),
    ("call 098765-43210", "call 9876543210"),
    ("pay Rs.5,000 now", "pay rs 5000 now"),
    ("only ₹1.5 lakh", "only rs 150000"),
    ("earn 5k rs daily", "earn rs 5000 daily"),
    ("a/c xx1234", "account xx1234"),
])
def test_normalize(raw, expected):
    assert normalize(raw) == expected


def test_clean_input():
    assert clean_input("  hi\x00 there ") == "hi there"
    with pytest.raises(InputError):
        clean_input("   ")
    with pytest.raises(InputError):
        clean_input("x" * (config.MAX_MESSAGE_CHARS + 1))


def test_defang_makes_links_unclickable():
    out = defang("go to https://evil.example.test/x and bit.ly/abc")
    assert "https://" not in out and "hxxps://" in out and "[.]" in out
    assert "bit[.]ly" in out


def test_mask_hides_private_numbers():
    out = mask("Call +91 9876543210, OTP 482913, card 4111111111111111, mail ravi.k@x.com")
    assert "9876543210" not in out and "482913" not in out and "4111" not in out and "ravi.k" not in out


def test_rate_limiter():
    now = [0.0]
    rl = RateLimiter(2, window_s=10, clock=lambda: now[0])
    assert rl.allow() and rl.allow() and not rl.allow()
    now[0] = 11
    assert rl.allow()
