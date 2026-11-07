"""
gmail_auth_web.py
-------------------
Web-based OAuth flow for Gmail, used when this app is deployed
publicly (e.g. Streamlit Community Cloud) rather than run on a
single user's own machine. See gmail_auth.py for the desktop-app
version used during local development - that file is untouched by
this one, and app.py automatically picks whichever flow fits based
on whether cloud secrets are configured.

Why this needs to be a different flow, not just a config change:
The desktop flow (gmail_auth.py) opens a temporary server ON THE
MACHINE RUNNING THE CODE to catch Google's login response. That only
works because, locally, the person running the code and the person
logging in are the same person on the same machine. Once this code
runs on a shared cloud server instead, that trick breaks: the server
can't open a browser or bind a port on a random visitor's device.

The web flow instead:
1. Generates a login LINK the visitor's own browser follows to
   Google's site.
2. Google redirects the visitor's browser back to this app's own
   public URL with a `code` parameter attached.
3. This app reads that code from the URL (via st.query_params) and
   exchanges it for an access token - entirely through HTTP requests,
   no local server needed on either side.

Multi-visitor safety:
Each visitor's Gmail token is stored in st.session_state, which is
scoped to that individual visitor's browser session only - never
written to disk, never shared between visitors, and automatically
discarded when their session ends. This is a deliberate privacy
choice appropriate for a public demo: the server never accumulates a
growing list of strangers' access tokens.

CSRF protection (the `state` parameter):
A random nonce and timestamp are signed with the OAuth client secret
using HMAC-SHA256. Google echoes the value back on redirect, and this
module verifies the signature and age before accepting the one-time
code. Signing it (rather than keeping it only in session state) means
the check still works if Streamlit creates a fresh session for the
redirect - while still making it impossible for an attacker to forge
a valid state.

Credentials handling:
The OAuth client ID/secret for this web flow are read from Streamlit
secrets (st.secrets), configured in Streamlit Cloud's dashboard - NOT
committed to the repository, exactly like credentials.json is kept
out of git in the desktop-flow setup.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

import streamlit as st
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# A login link is only valid for ten minutes.
STATE_TTL_SECONDS = 600


def is_cloud_configured():
    """True once this deployment has a complete Gmail web-OAuth secrets
    block in Streamlit Cloud's Secrets manager. If false, app.py falls
    back to the local desktop flow instead."""
    try:
        gmail = st.secrets["gmail"]
        return all(key in gmail for key in ("client_id", "client_secret", "redirect_uri"))
    except Exception:
        return False


def _client_config():
    return {
        "web": {
            "client_id": st.secrets["gmail"]["client_id"],
            "client_secret": st.secrets["gmail"]["client_secret"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [st.secrets["gmail"]["redirect_uri"]],
        }
    }


def _state_secret() -> bytes:
    """Key used to sign the OAuth state. The client secret is already a
    server-only value, so it never needs to be sent to the browser."""
    return str(st.secrets["gmail"]["client_secret"]).encode("utf-8")


def _sign(payload: str) -> str:
    return hmac.new(_state_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def make_state() -> str:
    """Create a signed, timestamped, single-use-ish state value."""
    nonce = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("=")
    payload = f"{nonce}.{int(time.time())}"
    return f"{payload}.{_sign(payload)}"


def verify_state(state: str | None) -> bool:
    """Accept only a state this app signed, and only while fresh."""
    if not state:
        return False
    try:
        nonce, timestamp, signature = state.rsplit(".", 2)
        payload = f"{nonce}.{timestamp}"
        if not hmac.compare_digest(signature, _sign(payload)):
            return False
        return (time.time() - int(timestamp)) <= STATE_TTL_SECONDS
    except Exception:
        return False


def get_authorization_url():
    """Builds the link the visitor clicks to start Google login."""
    flow = Flow.from_client_config(
        _client_config(), scopes=SCOPES,
        redirect_uri=st.secrets["gmail"]["redirect_uri"],
        autogenerate_code_verifier=False,
    )
    auth_url, _state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes=True,
        prompt="consent",
        state=make_state(),
    )
    return auth_url


def handle_redirect_callback():
    """Call this near the top of the app on every load.

    If Google just redirected the visitor back with a `code`
    parameter, this exchanges it for credentials and stores them in
    THIS visitor's session only. Safe to call when there's no code
    present - it just does nothing in that case.

    Guards against Streamlit's automatic reruns submitting the same
    one-time authorization code to Google more than once - Google
    accepts a code exactly once and rejects any repeat with
    invalid_grant, which otherwise surfaces as a crash on screen.
    """
    params = st.query_params
    code = params.get("code")
    returned_state = params.get("state")
    if not code:
        return False

    if st.session_state.get("_gmail_last_code_seen") == code:
        # Already handled (successfully or not) on an earlier rerun
        # of this same script - don't resubmit it.
        st.query_params.clear()
        return is_connected()
    st.session_state["_gmail_last_code_seen"] = code

    # Fail closed: an absent, forged, or expired state is rejected.
    if not verify_state(returned_state):
        st.query_params.clear()
        st.error("Login could not be verified (state mismatch). Please try connecting again.")
        return False

    try:
        flow = Flow.from_client_config(
            _client_config(), scopes=SCOPES,
            redirect_uri=st.secrets["gmail"]["redirect_uri"],
            autogenerate_code_verifier=False,
        )
        flow.fetch_token(code=code)
    except Exception as e:
        st.query_params.clear()
        st.error(f"Google login could not be completed ({e}). Please click Connect Gmail Account again.")
        return False

    creds = flow.credentials
    st.session_state["gmail_creds"] = creds.to_json()
    st.query_params.clear()
    return True


def is_connected():
    return "gmail_creds" in st.session_state


def disconnect():
    st.session_state.pop("gmail_creds", None)
    st.session_state.pop("_gmail_last_code_seen", None)


def get_gmail_service():
    if not is_connected():
        raise RuntimeError("Gmail is not connected for this session.")
    creds_info = json.loads(st.session_state["gmail_creds"])
    creds = Credentials.from_authorized_user_info(creds_info, SCOPES)
    return build("gmail", "v1", credentials=creds)


def get_connected_email(service):
    profile = service.users().getProfile(userId="me").execute()
    return profile.get("emailAddress", "unknown")
