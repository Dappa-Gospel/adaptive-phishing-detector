"""
classifier.py
--------------
Shared classification logic used by BOTH app.py (Streamlit interface)
and gmail_scanner.py (live email integration). Pulling this into one
module means the two front-ends can never drift out of sync with each
other - a message is scored exactly the same way whether it arrives
through the Chat page or through a Gmail inbox scan.

The decision rule is also imported by train_model.py, so the metrics
reported in the app describe the *same* rule the app actually uses.
"""

from __future__ import annotations

import re
from pathlib import Path

import joblib

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"
VECTORIZER_PATH = BASE_DIR / "models" / "vectorizer.pkl"

URGENT_KEYWORDS = ["urgent", "immediately", "act now", "verify now",
                   "final notice", "act immediately", "expire", "suspended"]
PHISHING_KEYWORDS = ["prize", "winner", "free", "bitcoin", "claim", "gift card"]
CREDENTIAL_KEYWORDS = ["password", "pin", "cvv", "otp", "one-time password",
                       "card number", "account number", "routing number",
                       "social security", "login and password", "ssn"]
SHORT_URL_PATTERNS = ["bit.ly", "tinyurl", "t.co", "goo.gl"]

# Thresholds used by the hybrid decision. Keep these in one place.
CREDENTIAL_THRESHOLD = 0.30   # explicit credential request: lower the bar
RULE_HIT_THRESHOLD = 0.50     # at least one concrete red flag
NO_RULE_THRESHOLD = 0.80      # no red flags at all: require strong ML confidence

# Only flag hyphenated domains that contain a phishing-style action word,
# so legitimate domains like `my-company.com` are not reported.
_SUSPICIOUS_HYPHEN_DOMAIN = re.compile(
    r"\b[a-z0-9]+-(?:secure|verify|login|signin|account|update|support|"
    r"billing|confirm|payment|pay|auth)[a-z0-9-]*\.(?:com|net|org)\b"
)

_model = None
_vectorizer = None


def _load():
    global _model, _vectorizer
    if _model is None or _vectorizer is None:
        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)
    return _model, _vectorizer


def reset_model():
    """Drop the cached model so a retrain takes effect without a full
    process restart."""
    global _model, _vectorizer
    _model = None
    _vectorizer = None


def has_credential_request(text: str) -> bool:
    text_lower = text.lower()
    return any(k in text_lower for k in CREDENTIAL_KEYWORDS)


def analyze_reasons(text: str, include_fallback: bool = True) -> list[str]:
    """Rule-based explanation layer - does not affect the verdict on
    its own, but see decide() for how it gates the ML score.

    Set include_fallback=False to get only genuine rule hits, with no
    filler text when nothing matched - used by decide() to detect
    whether a message has ANY real red flag at all.
    """
    reasons = []
    text_lower = text.lower()

    if re.search(r"http[s]?://(?:\d{1,3}\.){3}\d{1,3}", text):
        reasons.append("Contains an IP address instead of a domain name")

    for pattern in SHORT_URL_PATTERNS:
        if pattern in text_lower:
            reasons.append(f"Uses a URL shortener ({pattern})")

    if any(k in text_lower for k in URGENT_KEYWORDS):
        reasons.append("Contains urgent pressure language")

    if any(k in text_lower for k in PHISHING_KEYWORDS):
        reasons.append("Contains common phishing keywords (prize, free, claim, etc.)")

    if any(k in text_lower for k in CREDENTIAL_KEYWORDS):
        reasons.append("Directly requests sensitive credentials (password, PIN, card number, etc.)")

    if "http://" in text_lower and "https://" not in text_lower:
        reasons.append("Link does not use secure HTTPS")

    if _SUSPICIOUS_HYPHEN_DOMAIN.search(text_lower):
        reasons.append("Domain contains a suspicious hyphenated pattern")

    if not reasons and include_fallback:
        reasons.append("Message pattern matches known phishing language")

    return reasons


def decide(phishing_prob: float, text: str) -> tuple[bool, float]:
    """Apply the hybrid threshold and return (is_phishing, threshold).

    This is the single source of truth for the decision rule. Both the
    live classifier and the offline evaluation call it.
    """
    if has_credential_request(text):
        threshold = CREDENTIAL_THRESHOLD
    elif analyze_reasons(text, include_fallback=False):
        threshold = RULE_HIT_THRESHOLD
    else:
        # No concrete red flags at all - only convict on strong ML
        # confidence. This prevents a near-coin-flip score on a short,
        # ordinary message from producing a false PHISHING verdict.
        threshold = NO_RULE_THRESHOLD
    return phishing_prob >= threshold, threshold


def classify(text: str) -> tuple[str, float, list[str]]:
    """Hybrid decision: ML probability combined with rule-based gates."""
    if not text or not text.strip():
        # No evidence at all is not evidence of phishing.
        return "SAFE", 0.0, []

    model, vectorizer = _load()
    vec = vectorizer.transform([text])
    proba = model.predict_proba(vec)[0]     # [P(safe), P(phishing)]
    phishing_prob = float(proba[1])

    is_phishing, _threshold = decide(phishing_prob, text)

    verdict = "PHISHING" if is_phishing else "SAFE"
    shown_confidence = phishing_prob if is_phishing else (1 - phishing_prob)
    confidence = round(shown_confidence * 100, 1)
    reasons = analyze_reasons(text) if is_phishing else []
    return verdict, confidence, reasons
