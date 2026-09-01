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

Credentials handling:
The OAuth client ID/secret for this web flow are read from Streamlit
secrets (st.secrets), configured in Streamlit Cloud's dashboard - NOT
committed to the repository, exactly like credentials.json is kept
out of git in the desktop-flow setup.
"""

import json

import streamlit as st
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]


def is_cloud_configured():
    """True once this deployment has Gmail web-OAuth secrets set up
    in Streamlit Cloud's Secrets manager. If false, app.py falls back
    to the local desktop flow instead."""
    try:
        return "gmail" in st.secrets and "client_id" in st.secrets["gmail"]
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


def get_authorization_url():
    """Builds the link the visitor clicks to start Google login. A
    random `state` value is stored in this visitor's session and
    later checked on return, as a CSRF protection - it proves the
    person completing login is the same person who started it.

    PKCE (autogenerate_code_verifier) is deliberately disabled here.
    PKCE exists to protect "public" clients that can't safely hold a
    secret (like mobile apps). This app authenticates with Google
    using a client_secret instead (a "confidential" client), which
    already proves its identity without needing PKCE. Using PKCE here
    would require the code_verifier generated for the login link to
    still be available later when Google redirects back - but that
    redirect is a real browser navigation, not just an in-app rerun,
    and isn't guaranteed to land back in the exact same Streamlit
    session. Skipping PKCE entirely avoids depending on that."""
    flow = Flow.from_client_config(
        _client_config(), scopes=SCOPES,
        redirect_uri=st.secrets["gmail"]["redirect_uri"],
        autogenerate_code_verifier=False,
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    st.session_state["_gmail_oauth_state"] = state
    return auth_url


def handle_redirect_callback():
    """Call this near the top of the Settings page on every load.
    If Google just redirected the visitor back with a `code`
    parameter, this exchanges it for credentials and stores them in
    THIS visitor's session only. Safe to call when there's no code
    present - it just does nothing in that case.

    Guards against Streamlit's automatic reruns submitting the same
    one-time authorization code to Google more than once - Google
    accepts a code exactly once and rejects any repeat with
    invalid_grant, which otherwise surfaces as a crash on screen."""
    params = st.query_params
    code = params.get("code")
    returned_state = params.get("state")
    if not code:
        return False

    if st.session_state.get("_gmail_last_code_seen") == code:
        # Already handled (successfully or not) on an earlier rerun
        # of this same script - don't resubmit it.
        return is_connected()
    st.session_state["_gmail_last_code_seen"] = code

    expected_state = st.session_state.get("_gmail_oauth_state")
    if expected_state and returned_state != expected_state:
        st.error("Login could not be verified (state mismatch). Please try connecting again.")
        st.query_params.clear()
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
    st.session_state.pop("_gmail_oauth_state", None)


def get_gmail_service():
    if not is_connected():
        raise RuntimeError("Gmail is not connected for this session.")
    creds_info = json.loads(st.session_state["gmail_creds"])
    creds = Credentials.from_authorized_user_info(creds_info, SCOPES)
    return build("gmail", "v1", credentials=creds)


def get_connected_email(service):
    profile = service.users().getProfile(userId="me").execute()
    return profile.get("emailAddress", "unknown")
