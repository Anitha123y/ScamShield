"""ScamShield detection engine - decides SCAM / SUSPICIOUS / SAFE for a message."""
from .detector import Result, analyze
from .language import detect_language
from .normalize import normalize

__all__ = ["Result", "analyze", "detect_language", "normalize"]
__version__ = "3.0.0"
