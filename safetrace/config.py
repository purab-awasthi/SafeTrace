"""
Configuration constants for SafeTrace.

Centralises all tunable parameters — thresholds, paths, token lists,
and pattern dictionaries — so they can be adjusted in one place.
"""

import logging
from pathlib import Path

# --- Logging ---
LOG_FORMAT = "%(levelname)s | %(name)s | %(message)s"
LOG_LEVEL = logging.INFO

# --- Paths ---
PACKAGE_DIR = Path(__file__).resolve().parent
MODELS_DIR = PACKAGE_DIR / "models"

URL_MODEL_PATH = MODELS_DIR / "url_model.joblib"
EMAIL_MODEL_PATH = MODELS_DIR / "email_model.joblib"
EMAIL_VECTORIZER_PATH = MODELS_DIR / "email_vectorizer.joblib"

# --- Risk thresholds ---
HIGH_RISK_THRESHOLD = 0.75
MEDIUM_RISK_THRESHOLD = 0.45

# --- Suspicious tokens found in phishing URLs ---
SUSPICIOUS_TOKENS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "signin", "ebay", "paypal", "free", "lucky",
    "winner", "prize", "click", "urgent", "suspend", "alert",
]

# --- Suspicious TLDs commonly abused in phishing ---
SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz",
    ".club", ".work", ".info", ".ru", ".cn", ".pw",
]

# --- Phishing language patterns for email/text analysis ---
PHISHING_PATTERNS = {
    "urgency": [
        "act now", "immediately", "urgent", "expire", "hurry",
        "limited time", "deadline", "right away", "don't delay",
    ],
    "threats": [
        "account will be suspended", "unauthorized access",
        "your account has been compromised", "security alert",
        "failure to verify", "will be locked", "permanently disabled",
    ],
    "credential_request": [
        "verify your identity", "confirm your account",
        "update your information", "enter your password",
        "social security", "credit card number", "bank account",
    ],
    "too_good_to_be_true": [
        "congratulations", "you have won", "free gift",
        "claim your prize", "million dollars", "selected as winner",
        "lottery", "inheritance",
    ],
    "impersonation": [
        "dear customer", "dear user", "dear valued",
        "official notification", "from the desk of",
        "management team", "support team",
    ],
}
