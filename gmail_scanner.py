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
import os
import time
from datetime import datetime

from classifier import classify
from gmail_auth import get_gmail_service

LOG_PATH = "logs/scan_log.csv"
LABEL_NAME = "⚠️ Possible Phishing"
POLL_SECONDS = 30


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


def extract_text(payload):
    """Pulls the plain-text body out of a Gmail message payload,
    which can be nested in different ways depending on the email."""
    if "parts" in payload:
        for part in payload["parts"]:
            if part.get("mimeType") == "text/plain":
                data = part["body"].get("data", "")
                if data:
                    return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
            elif "parts" in part:
                text = extract_text(part)
                if text:
                    return text
    else:
        data = payload.get("body", {}).get("data", "")
        if data:
            return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
    return ""


def get_subject(headers):
    for h in headers:
        if h["name"].lower() == "subject":
            return h["value"]
    return "(no subject)"


def notify_desktop(title, message):
    """Best-effort desktop notification. Works out of the box on Mac;
    silently does nothing on platforms without a notifier available,
    since the Gmail label + log entry are the reliable source of
    truth regardless."""
    try:
        import platform
        if platform.system() == "Darwin":
            os.system(f"""osascript -e 'display notification "{message}" with title "{title}"' """)
        elif platform.system() == "Linux":
            os.system(f'notify-send "{title}" "{message}"')
    except Exception:
        pass


def log_scan(text, verdict, confidence):
    import csv
    with open(LOG_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now(), text[:80], verdict, confidence])


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
        seen_ids.add(msg_id)

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


def scan_recent_inbox_once(service=None, max_results=10):
    """One-shot scan used by the Streamlit 'Scan inbox now' button:
    checks the most recent inbox messages regardless of whether
    they've been seen before, applies labels/logs as normal, and
    returns the results for display in the UI.

    Accepts an already-authenticated `service` object so this same
    function works with either the local desktop auth flow or the
    public web auth flow - the caller decides which one built the
    service, this function doesn't need to know or care."""
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
        seen_ids.add(m["id"])

    while True:
        try:
            scan_inbox(service, label_id, seen_ids)
        except Exception as e:
            print(f"Error during scan: {e}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
