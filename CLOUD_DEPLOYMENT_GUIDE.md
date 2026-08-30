# Cloud Deployment Guide

This covers hosting the project publicly on Streamlit Community Cloud,
with the Gmail integration working for any visitor - not just you.

## Part 1: Host the app

1. Push this project to a GitHub repository. Your `.gitignore` already
   excludes `credentials.json`, `gmail_token.json`, and
   `.streamlit/secrets.toml`, so none of your personal credentials
   will be uploaded.
2. Go to https://share.streamlit.io, sign in with GitHub, click
   **New app**, select your repository, set the main file to `app.py`,
   and click **Deploy**.
3. Within a few minutes you'll get a public URL like
   `https://your-app-name.streamlit.app`.

At this point, the Chat, History, Statistics, and About pages already
work for anyone who visits. The Gmail section will show the local
"Connect Gmail Account" flow, which **will not work for visitors**
until you complete Part 2.

## Part 2: Set up a Web-type OAuth client for the public URL

Your existing `credentials.json` (Desktop app type) only works for
local runs — it can't be used for the public deployment. You need a
**second, separate** OAuth client of type **Web application**.

1. Go back to https://console.cloud.google.com/, into the same
   project you used before (or a new one).
2. **APIs & Services → Credentials → Create Credentials → OAuth
   client ID**
3. Application type: **Web application** (not Desktop app this time)
4. Under **Authorized redirect URIs**, click **Add URI** and enter
   your exact deployed URL, e.g.
   `https://your-app-name.streamlit.app`
   (No trailing slash, no extra path — Google requires this to match
   exactly what the app sends.)
5. Click **Create**. This time, don't download a JSON file — instead,
   copy the **Client ID** and **Client secret** shown on screen; you'll
   paste these into Streamlit's secrets manager next.
6. Go back to **OAuth consent screen → Test users** and add the Gmail
   address of anyone you want to be able to use the live Gmail feature
   (e.g. your supervisor, examiners) — while the app is in "Testing"
   mode, only these listed accounts can complete login. Going beyond
   100 test users, or making it open to literally anyone, requires
   Google's formal verification process (a separate, longer process
   involving a privacy policy and app review — reasonable to mention
   as a limitation in your report rather than pursue for a student
   project).

## Part 3: Add the secrets to Streamlit Cloud

1. On your app's page at https://share.streamlit.io, click the **⋮**
   menu → **Settings → Secrets**
2. Paste the following, filling in your actual values from Part 2:

```toml
[gmail]
client_id = "your-client-id.apps.googleusercontent.com"
client_secret = "your-client-secret"
redirect_uri = "https://your-app-name.streamlit.app"
```

3. Click **Save**. The app will automatically restart.

The app detects these secrets automatically (`gmail_auth_web.py`'s
`is_cloud_configured()`) and switches into the public web-OAuth flow
— no code changes needed. Locally, without these secrets set, the app
keeps using the original desktop flow exactly as before, so your local
setup is completely unaffected.

## How the public flow differs from the local one

| | Local (Desktop flow) | Public (Web flow) |
|---|---|---|
| Who can connect | Just you | Any test user you add |
| Where the token is stored | `gmail_token.json` on your disk | Your browser's session only, in server memory |
| How long the connection lasts | Until you disconnect | Until you close the tab or disconnect |
| Multiple people at once | N/A (one user, one machine) | Each visitor's Gmail access is completely separate and invisible to others |

This session-only storage for the public version is a deliberate
privacy choice: the server never accumulates a growing list of
strangers' Gmail tokens sitting on disk.

## Testing it yourself

Visit your deployed URL, go to **Settings → Gmail Integration**, and
click **Connect Gmail Account**. You should be redirected to Google's
real login page, and after approving, redirected back to your app
already connected. If you see "Error 400: redirect_uri_mismatch",
double check the URL in Google Cloud Console (Part 2, step 4) matches
your deployed URL **exactly**, including `https://` and no trailing
slash.
