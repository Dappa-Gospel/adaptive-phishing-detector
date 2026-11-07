import time

import gmail_auth_web


def _fixed_secret(monkeypatch, secret="test-secret"):
    monkeypatch.setattr(gmail_auth_web, "_state_secret", lambda: secret.encode("utf-8"))


def _state_with_timestamp(timestamp):
    nonce = "abc123"
    payload = f"{nonce}.{timestamp}"
    return f"{payload}.{gmail_auth_web._sign(payload)}"


def test_state_roundtrip_is_valid(monkeypatch):
    _fixed_secret(monkeypatch)
    assert gmail_auth_web.verify_state(gmail_auth_web.make_state()) is True


def test_tampered_state_is_rejected(monkeypatch):
    _fixed_secret(monkeypatch)
    state = gmail_auth_web.make_state()
    forged = state[:-1] + ("0" if state[-1] != "0" else "1")
    assert gmail_auth_web.verify_state(forged) is False


def test_state_signed_with_other_secret_is_rejected(monkeypatch):
    _fixed_secret(monkeypatch, "secret-one")
    state = gmail_auth_web.make_state()
    _fixed_secret(monkeypatch, "secret-two")
    assert gmail_auth_web.verify_state(state) is False


def test_missing_state_is_rejected(monkeypatch):
    _fixed_secret(monkeypatch)
    assert gmail_auth_web.verify_state(None) is False
    assert gmail_auth_web.verify_state("") is False
    assert gmail_auth_web.verify_state("not-a-state") is False


def test_expired_state_is_rejected(monkeypatch):
    _fixed_secret(monkeypatch)
    old = int(time.time()) - gmail_auth_web.STATE_TTL_SECONDS - 5
    assert gmail_auth_web.verify_state(_state_with_timestamp(old)) is False


def test_fresh_state_within_ttl_is_accepted(monkeypatch):
    _fixed_secret(monkeypatch)
    recent = int(time.time()) - 10
    assert gmail_auth_web.verify_state(_state_with_timestamp(recent)) is True
