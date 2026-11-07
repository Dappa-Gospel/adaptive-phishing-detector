import classifier


def test_empty_input_is_safe():
    verdict, confidence, reasons = classifier.classify("")
    assert verdict == "SAFE"
    assert confidence == 0.0
    assert reasons == []


def test_whitespace_input_is_safe():
    assert classifier.classify("   \n\t ")[0] == "SAFE"


def test_credential_request_is_phishing():
    verdict, _confidence, reasons = classifier.classify("Input your bank password now.")
    assert verdict == "PHISHING"
    assert any("credentials" in r for r in reasons)


def test_obvious_phishing_link_is_phishing():
    verdict, _confidence, _reasons = classifier.classify(
        "Your PayPal account is suspended. Verify at http://paypal-secure-verify.com/verify"
    )
    assert verdict == "PHISHING"


def test_ordinary_message_is_safe():
    assert classifier.classify("Hey, are we still meeting for lunch tomorrow?")[0] == "SAFE"


def test_reasons_include_fallback_flag():
    assert classifier.analyze_reasons("hello there", include_fallback=False) == []
    assert classifier.analyze_reasons("hello there", include_fallback=True) == [
        "Message pattern matches known phishing language"
    ]


def test_credential_request_lowers_threshold():
    is_phishing, threshold = classifier.decide(0.35, "please send your password")
    assert is_phishing is True
    assert threshold == classifier.CREDENTIAL_THRESHOLD


def test_no_rule_hit_requires_strong_confidence():
    is_phishing, threshold = classifier.decide(0.60, "how are you doing")
    assert is_phishing is False
    assert threshold == classifier.NO_RULE_THRESHOLD


def test_rule_hit_uses_mid_threshold():
    is_phishing, threshold = classifier.decide(0.55, "verify now at http://1.2.3.4/login")
    assert is_phishing is True
    assert threshold == classifier.RULE_HIT_THRESHOLD


def test_legitimate_hyphenated_domain_not_flagged():
    reasons = classifier.analyze_reasons("Please check my-company.com portal")
    assert not any("hyphenated" in r for r in reasons)


def test_suspicious_hyphenated_domain_flagged():
    reasons = classifier.analyze_reasons("Visit account-verify-now.com to continue")
    assert any("hyphenated" in r for r in reasons)
