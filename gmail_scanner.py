"""
gmail_scanner.py
-----------------
Connects the phishing detector to a real Gmail inbox.

How it works, in plain terms:
1. You log in once with your Google account (a browser window opens
   for you to approve access - this is the same consent screen every
   legitimate app that reads your Gmail uses).
2. Every {POLL_SECONDS} seconds, the script checks for new emails
   that have arrived since the last check.
3. Each new email's subject + body is run through the exact same
   Naive Bayes + hybrid rule model used in the Chat page
   (classifier.py), so results are always consistent with the rest
   of the project.
4. If an email is flagged PHISHING:
      - A Gmail label "⚠️ Possible Phishing" is created (if it
        doesn't exist yet) and applied to the email, so it's visibly
        marked inside Gmail itself.
      - The result is logged to logs/scan_log.csv, exactly like a
        manual Chat scan, so it shows up in the app's History and
        Statistics pages too.
      - A desktop notification pops up so the user sees it
        immediately, without having to open Gmail.
   The email is NEVER deleted, moved, or blocked automatically - the
   user always makes the final call whether to proceed, per the
   project's design goal (this is a decision-support tool, not an
   auto-blocker).

Setup required before running (see SETUP_GUIDE.md for full steps):
- A Google Cloud project with the Gmail API enabled
- An OAuth "credentials.json" file downloaded into this folder
- pip install -r requirements.txt (includes the Google API packages)

This uses polling (checking every N seconds) rather than Gmail's
push-notification system (which needs a Cloud Pub/Sub subscription
and a public webhook URL) because polling needs no public server and
is far simpler to set up and defend for a final year project. This
trade-off is worth mentioning explicitly in your report.
"""

import base64
import html
import platform
import re
import subprocess
import time

from classifier import classify
from gmail_auth import get_gmail_service
import storage

LABEL_NAME = "⚠️ Possible Phishing"
POLL_SECONDS = 30
MAX_SEEN_IDS = 1000


def get_or_create_label(service, label_name):
    labels = service.users().labels().list(userId="me").execute().get("labels", [])
    for label in labels:
        if label["name"] == label_name:
            return label["id"]
    new_label = service.users().labels().create(
        userId="me",
        body={"name": label_name, "labelListVisibility": "labelShow",
              "messageListVisibility": "show"},
    ).execute()
    return new_label["id"]


def _decode_part(part):
    data = part.get("body", {}).get("data", "")
    if not data:
        return ""
    return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")


def _strip_html(markup):
    """Turn an HTML email body into readable text without executing
    or keeping any markup."""
    markup = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", markup, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", markup)
    return html.unescape(text)


def extract_text(payload):
    """Pulls the readable body out of a Gmail message payload.

    Prefers text/plain, then falls back to text/html. The old version
    only looked at text/plain, so HTML-only emails (common for real
    phishing) were scored on the subject alone.
    """
    plain_parts, html_parts = [], []

    def walk(part):
        mime = part.get("mimeType", "")
        if mime == "text/plain":
            plain_parts.append(_decode_part(part))
        elif mime == "text/html":
            html_parts.append(_strip_html(_decode_part(part)))
        for child in part.get("parts") or []:
            walk(child)

    walk(payload)

    text = " ".join(t for t in plain_parts if t).strip()
    if not text:
        text = " ".join(t for t in html_parts if t).strip()
    return re.sub(r"\s+", " ", text)


def get_subject(headers):
    for h in headers:
        if h["name"].lower() == "subject":
            return h["value"]
    return "(no subject)"


def _applescript_escape(value):
    """Escape a value for safe use inside an AppleScript string.

    The previous implementation interpolated the email subject
    straight into a shell command, which allowed an attacker to run
    arbitrary commands by sending a crafted subject. Values are now
    passed as a single argv element, and this escaping is an extra
    layer for AppleScript itself.
    """
    return (str(value)
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", " ")
            .replace("\r", " "))


def notify_desktop(title, message):
    """Best-effort desktop notification. Works out of the box on Mac;
    silently does nothing on platforms without a notifier available,
    since the Gmail label + log entry are the reliable source of
    truth regardless.

    Uses list-form subprocess calls (never a shell) so an email
    subject can never be interpreted as a command.
    """
    try:
        system = platform.system()
        if system == "Darwin":
            script = (
                f'display notification "{_applescript_escape(message)}" '
                f'with title "{_applescript_escape(title)}"'
            )
            subprocess.run(["osascript", "-e", script],
                           check=False, capture_output=True, timeout=5)
        elif system == "Linux":
            subprocess.run(["notify-send", str(title), str(message)],
                           check=False, capture_output=True, timeout=5)
    except Exception:
        # Notifications are a nice-to-have; the label and log are the
        # reliable record.
        pass


def log_scan(text, verdict, confidence):
    storage.append_scan_log(text, verdict, confidence)


def _remember(seen_ids, msg_id):
    """Add a message id and keep the set bounded for long-running
    monitors."""
    seen_ids.add(msg_id)
    while len(seen_ids) > MAX_SEEN_IDS:
        seen_ids.pop()


def scan_inbox(service, label_id, seen_ids):
    """Scans for new inbox messages not yet in seen_ids. Returns a
    list of result dicts so callers (the CLI loop below, or the
    Streamlit 'Scan inbox now' button) can both use this."""
    results_out = []
    results = service.users().messages().list(
        userId="me", labelIds=["INBOX"], maxResults=15
    ).execute()
    messages = results.get("messages", [])

    for msg_ref in messages:
        msg_id = msg_ref["id"]
        if msg_id in seen_ids:
            continue
        _remember(seen_ids, msg_id)

        msg = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
        headers = msg["payload"].get("headers", [])
        subject = get_subject(headers)
        body = extract_text(msg["payload"])
        combined_text = f"{subject}. {body}"[:2000]  # cap length for speed

        verdict, confidence, reasons = classify(combined_text)
        log_scan(f"[Gmail] {subject}", verdict, confidence)

        if verdict == "PHISHING":
            service.users().messages().modify(
                userId="me", id=msg_id, body={"addLabelIds": [label_id]}
            ).execute()
            reason_text = "; ".join(reasons[:2])
            print(f"🚨 PHISHING ({confidence}%): {subject}\n   Reasons: {reason_text}")
            notify_desktop("⚠️ Possible Phishing Email", f"{subject} ({confidence}% confidence)")
        else:
            print(f"✅ SAFE ({confidence}%): {subject}")

        results_out.append({
            "subject": subject, "verdict": verdict,
            "confidence": confidence, "reasons": reasons,
        })

    return results_out


def scan_recent_inbox_once(service=None, max_results=10, seen_ids=None):
    """One-shot scan used by the Streamlit 'Scan inbox now' button.

    Accepts an already-authenticated `service` object so this same
    function works with either the local desktop auth flow or the
    public web auth flow - the caller decides which one built the
    service, this function doesn't need to know or care.

    `seen_ids` is optional. When the caller passes the session's set
    of already-checked message ids, repeat clicks no longer re-scan
    and re-log the same emails (which used to inflate the Statistics
    page). Pass None to force a full re-scan.
    """
    if service is None:
        service = get_gmail_service()
    label_id = get_or_create_label(service, LABEL_NAME)
    results = service.users().messages().list(
        userId="me", labelIds=["INBOX"], maxResults=max_results
    ).execute()
    messages = results.get("messages", [])

    results_out = []
    for msg_ref in messages:
        msg_id = msg_ref["id"]
        if seen_ids is not None:
            if msg_id in seen_ids:
                continue
            _remember(seen_ids, msg_id)

        msg = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
        headers = msg["payload"].get("headers", [])
        subject = get_subject(headers)
        body = extract_text(msg["payload"])
        combined_text = f"{subject}. {body}"[:2000]

        verdict, confidence, reasons = classify(combined_text)
        log_scan(f"[Gmail] {subject}", verdict, confidence)

        if verdict == "PHISHING":
            service.users().messages().modify(
                userId="me", id=msg_id, body={"addLabelIds": [label_id]}
            ).execute()

        results_out.append({
            "subject": subject, "verdict": verdict,
            "confidence": confidence, "reasons": reasons,
        })

    return results_out


def main():
    print("Connecting to Gmail...")
    service = get_gmail_service()
    label_id = get_or_create_label(service, LABEL_NAME)
    print(f"Connected. Watching inbox every {POLL_SECONDS}s. Press Ctrl+C to stop.\n")

    seen_ids = set()
    # On first run, mark current inbox as already-seen so we only
    # alert on genuinely NEW mail from this point forward.
    initial = service.users().messages().list(userId="me", labelIds=["INBOX"], maxResults=15).execute()
    for m in initial.get("messages", []):
        _remember(seen_ids, m["id"])

    while True:
        try:
            scan_inbox(service, label_id, seen_ids)
        except Exception as e:
            print(f"Error during scan: {e}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
