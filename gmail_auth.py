"""
gmail_auth.py
--------------
Handles connecting and disconnecting a Gmail account. Shared by both
app.py (the "Connect Gmail" button in Settings) and gmail_scanner.py
(the standalone continuous-monitoring script), so there is exactly
one place that manages the OAuth token.

Security practices this module follows:

1. The user's Gmail password is NEVER seen, entered, or stored by
   this project at all. Login happens entirely on Google's own page;
   this app only ever receives a limited-scope access token from
   Google afterward. This is the core security benefit of OAuth over
   asking a user to paste in a password.

2. Scope is limited to what's functionally required. gmail.modify is
   used because applying a label to a message (users.messages.modify)
   specifically requires it - Google's narrower gmail.labels scope
   only manages label definitions, not applying them to messages.
   Importantly, gmail.modify does NOT allow sending email and does
   NOT allow permanently deleting messages/threads - it is already
   narrower than the full-access https://mail.google.com/ scope.

3. The saved token (gmail_token.json) is treated as a sensitive
   credential: it's excluded from version control via .gitignore,
   and file permissions are locked down to the current user only
   right after it's written.

4. A visible "Disconnect" action deletes the local token immediately.
   The user can additionally revoke access at any time directly from
   their Google Account, independent of this app - see
   https://myaccount.google.com/permissions. Mentioning this
   independent revocation path matters: it means the user is never
   dependent on trusting this app's own disconnect button.

5. Data minimization: only the subject + a length-capped snippet of
   each email is ever written to logs/scan_log.csv (never the full
   email body), and nothing is sent to any third-party server other
   than Google's own Gmail API and the local classifier.
"""

import os
import stat

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# gmail.modify is the minimum scope that permits applying labels to
# messages (see module docstring point 2). It does NOT grant send or
# permanent-delete capability.
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
TOKEN_PATH = "gmail_token.json"
CREDENTIALS_PATH = "credentials.json"


def is_connected():
    return os.path.exists(TOKEN_PATH)


def _lock_down_token_file():
    """Restrict the token file to the current user only (rw-------),
    since it's equivalent in sensitivity to a session cookie."""
    try:
        os.chmod(TOKEN_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # best-effort; not all filesystems support chmod (e.g. some Windows setups)


def connect():
    """Runs the OAuth consent flow. Opens the user's browser to
    Google's own login/consent page - this app never sees their
    Gmail password. Returns the connected email address."""
    if not os.path.exists(CREDENTIALS_PATH):
        raise FileNotFoundError(
            "credentials.json not found. Follow SETUP_GUIDE.md to create "
            "your own Google Cloud OAuth credentials first."
        )
    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
    creds = flow.run_local_server(port=0)
    with open(TOKEN_PATH, "w") as f:
        f.write(creds.to_json())
    _lock_down_token_file()
    return get_connected_email(build("gmail", "v1", credentials=creds))


def disconnect():
    """Deletes the local token. The user's Google account itself is
    untouched - they can also revoke access independently at
    https://myaccount.google.com/permissions."""
    if os.path.exists(TOKEN_PATH):
        os.remove(TOKEN_PATH)


def get_gmail_service():
    """Returns an authenticated Gmail API client, refreshing the
    token automatically if it has expired. Raises if not connected."""
    if not is_connected():
        raise RuntimeError("Gmail is not connected. Call connect() first.")

    creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            with open(TOKEN_PATH, "w") as f:
                f.write(creds.to_json())
            _lock_down_token_file()
        else:
            raise RuntimeError("Gmail token is invalid and cannot be refreshed. Reconnect.")

    return build("gmail", "v1", credentials=creds)


def get_connected_email(service):
    profile = service.users().getProfile(userId="me").execute()
    return profile.get("emailAddress", "unknown")
