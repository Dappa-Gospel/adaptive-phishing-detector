import base64

import gmail_scanner


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii")


def test_applescript_escape_quotes_and_backslashes():
    assert gmail_scanner._applescript_escape('a"b') == 'a\\"b'
    assert gmail_scanner._applescript_escape("a\\b") == "a\\\\b"
    assert gmail_scanner._applescript_escape("a\nb") == "a b"


def test_extract_plain_text():
    payload = {"mimeType": "text/plain", "body": {"data": _b64("hello world")}}
    assert gmail_scanner.extract_text(payload) == "hello world"


def test_extract_nested_parts():
    payload = {
        "mimeType": "multipart/alternative",
        "parts": [
            {"mimeType": "text/plain", "body": {"data": _b64("nested body")}},
            {"mimeType": "text/html", "body": {"data": _b64("<p>ignored</p>")}},
        ],
    }
    assert gmail_scanner.extract_text(payload) == "nested body"


def test_extract_html_only_email():
    payload = {
        "mimeType": "text/html",
        "body": {"data": _b64("<html><body><p>Verify <b>now</b></p></body></html>")},
    }
    text = gmail_scanner.extract_text(payload)
    assert "Verify" in text
    assert "<" not in text


def test_extract_ignores_script_content():
    payload = {
        "mimeType": "text/html",
        "body": {"data": _b64("<style>.x{}</style><script>alert(1)</script><p>hello</p>")},
    }
    text = gmail_scanner.extract_text(payload)
    assert "hello" in text
    assert "alert" not in text


def test_notify_desktop_uses_list_form(monkeypatch):
    calls = []

    monkeypatch.setattr(gmail_scanner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(gmail_scanner.subprocess, "run", lambda args, **kwargs: calls.append(args))

    gmail_scanner.notify_desktop("Alert", "Invoice $(rm -rf /)")

    assert calls == [["notify-send", "Alert", "Invoice $(rm -rf /)"]]


def test_notify_desktop_macos_builds_single_argument(monkeypatch):
    calls = []

    monkeypatch.setattr(gmail_scanner.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(gmail_scanner.subprocess, "run", lambda args, **kwargs: calls.append(args))

    gmail_scanner.notify_desktop("Alert", 'x"; touch pwned; echo "')

    assert len(calls) == 1
    assert calls[0][0] == "osascript"
    assert calls[0][1] == "-e"
    # The malicious quote must be escaped inside the AppleScript string.
    assert '\\"' in calls[0][2]
