"""
classifier.py
--------------
Shared classification logic used by BOTH app.py (Streamlit interface)
and gmail_scanner.py (live email integration). Pulling this into one
module means the two front-ends can never drift out of sync with each
other - a message is scored exactly the same way whether it arrives
through the Chat page or through a Gmail inbox scan.
"""

import re
import joblib

MODEL_PATH = "models/phishing_model.pkl"
VECTORIZER_PATH = "models/vectorizer.pkl"

URGENT_KEYWORDS = ["urgent", "immediately", "act now", "verify now",
                    "final notice", "act immediately", "expire", "suspended"]
PHISHING_KEYWORDS = ["prize", "winner", "free", "bitcoin", "claim", "gift card"]
CREDENTIAL_KEYWORDS = ["password", "pin", "cvv", "otp", "one-time password",
                        "card number", "account number", "routing number",
                        "social security", "login and password", "ssn"]
SHORT_URL_PATTERNS = ["bit.ly", "tinyurl", "t.co", "goo.gl"]

_model = None
_vectorizer = None


def _load():
    global _model, _vectorizer
    if _model is None:
        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)
    return _model, _vectorizer


def analyze_reasons(text, include_fallback=True):
    """Rule-based explanation layer - does not affect the verdict on
    its own, but see classify() for how it now gates the ML score.
    Set include_fallback=False to get only genuine rule hits, with no
    filler text when nothing matched - used by classify() to detect
    whether a message has ANY real red flag at all."""
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

    if re.search(r"-[a-z]+\.(com|net|org)", text_lower):
        reasons.append("Domain contains a suspicious hyphenated pattern")

    if not reasons and include_fallback:
        reasons.append("Message pattern matches known phishing language")

    return reasons


def classify(text):
    """Hybrid decision combining the ML model with two rule-based
    gates, in opposite directions:

    1. LOWER the bar for messages that directly request credentials
       (password, PIN, card number, etc.) - these are almost never
       legitimate to send over chat/email, so the ML doesn't need to
       be independently confident.

    2. RAISE the bar for messages with ZERO real red flags at all.
       Short, generic messages (e.g. "how are you doing") often share
       almost no vocabulary with the training data, so the ML's
       probability for them sits close to a random 50/50 guess rather
       than reflecting genuine evidence. Without this gate, that near
       coin-flip score alone could tip an entirely ordinary message
       into a false PHISHING verdict. Requiring either a real rule
       hit OR high ML confidence (>=80%) before convicting protects
       against exactly that failure mode, while still allowing a
       well-written phishing attempt to be caught if the ML is
       genuinely confident about it."""
    model, vectorizer = _load()
    vec = vectorizer.transform([text])
    proba = model.predict_proba(vec)[0]     # [P(safe), P(phishing)]
    phishing_prob = proba[1]

    rule_hits = analyze_reasons(text, include_fallback=False)
    has_credential_request = any(k in text.lower() for k in CREDENTIAL_KEYWORDS)

    if has_credential_request:
        threshold = 0.30
    elif rule_hits:
        threshold = 0.50
    else:
        # No concrete red flags at all - only convict on strong ML confidence.
        threshold = 0.80

    is_phishing = phishing_prob >= threshold

    verdict = "PHISHING" if is_phishing else "SAFE"
    shown_confidence = phishing_prob if is_phishing else (1 - phishing_prob)
    confidence = round(shown_confidence * 100, 1)
    reasons = analyze_reasons(text) if is_phishing else []
    return verdict, confidence, reasons
