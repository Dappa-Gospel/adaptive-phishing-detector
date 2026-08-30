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


def analyze_reasons(text):
    """Rule-based explanation layer - does not affect the verdict,
    only helps explain why a PHISHING message was flagged."""
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

    if not reasons:
        reasons.append("Message pattern matches known phishing language")

    return reasons


def classify(text):
    """Hybrid decision: ML probability combined with a rule-based
    safety net. See generate_dataset.py / train_model.py notes for
    why short credential-harvesting messages need this."""
    model, vectorizer = _load()
    vec = vectorizer.transform([text])
    proba = model.predict_proba(vec)[0]     # [P(safe), P(phishing)]
    phishing_prob = proba[1]

    reasons = analyze_reasons(text)
    has_credential_request = any(k in text.lower() for k in CREDENTIAL_KEYWORDS)

    threshold = 0.30 if has_credential_request else 0.50
    is_phishing = phishing_prob >= threshold

    verdict = "PHISHING" if is_phishing else "SAFE"
    shown_confidence = phishing_prob if is_phishing else (1 - phishing_prob)
    confidence = round(shown_confidence * 100, 1)
    reasons = reasons if is_phishing else []
    return verdict, confidence, reasons
