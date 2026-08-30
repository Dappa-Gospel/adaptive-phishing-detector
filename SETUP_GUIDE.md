# Gmail Integration Setup Guide

This connects your phishing detector to a real Gmail inbox. You only
need to do this setup once.

## Step 1: Create a Google Cloud project

1. Go to https://console.cloud.google.com/
2. Click the project dropdown (top left) → **New Project**
3. Name it something like "Phishing Detector FYP" → Create

## Step 2: Enable the Gmail API

1. In the search bar at the top, search for **Gmail API**
2. Click it, then click **Enable**

## Step 3: Configure the OAuth consent screen

1. In the left sidebar, go to **APIs & Services → OAuth consent screen**
2. Choose **External** → Create
3. Fill in an App name (e.g. "Phishing Detector"), your email as the
   support email, and your email again as the developer contact
4. Click through the remaining steps with defaults (Save and Continue)
5. On the "Test users" step, click **Add users** and add your own
   Gmail address — this is required while the app is in testing mode

## Step 4: Create OAuth credentials

1. Go to **APIs & Services → Credentials**
2. Click **Create Credentials → OAuth client ID**
3. Application type: **Desktop app**
4. Name it anything, click **Create**
5. Click **Download JSON** on the credentials that were just created
6. Rename the downloaded file to exactly `credentials.json` and place
   it inside your `Adaptive-Phishing-System` project folder (same
   folder as `app.py`)

## Step 5: Connect from the app

Rather than running a separate script, you can now connect Gmail
directly from the Streamlit app:

```
python3 -m pip install -r requirements.txt
python3 -m streamlit run app.py
```

Go to **Settings → Gmail Integration → Connect Gmail Account**. A
browser window opens for you to sign in with Google and approve
access. Since the app is in "testing" mode, you'll see an "unverified
app" warning — click **Advanced → Go to [app name] (unsafe)**. This
is expected and safe since it's your own app that only you approved;
Google shows this warning for any app that hasn't gone through their
full public review process, which isn't necessary for a final year
project running on your own machine.

Once connected, you can click **Scan inbox now** to check your 10
most recent emails on demand, right from the Settings page.

## Alternative: continuous background monitoring

The in-app "Scan inbox now" button only checks when you click it.
For continuous monitoring that checks automatically every 30 seconds
(closer to a real deployment), run the standalone scanner instead,
in a separate terminal:

```
python3 gmail_scanner.py
```

Both use the same `gmail_auth.py` connection, so you only need to
connect once — either from the app or from this script — and both
will recognize it.

## How your data is kept safe

- **Your Gmail password is never seen or stored by this app.** Login
  happens entirely on Google's own consent page; this app only ever
  receives a limited-scope access token afterward.
- **Scope is limited to what's functionally required** —
  `gmail.modify`, which permits reading mail and applying labels.
  It does **not** permit sending email or permanently deleting
  anything, even though the name sounds broad.
- **The access token is stored locally** in `gmail_token.json`,
  excluded from version control via `.gitignore`, and its file
  permissions are locked to your user account only.
- **You can disconnect at any time** from Settings, or independently
  revoke access at
  [myaccount.google.com/permissions](https://myaccount.google.com/permissions)
  — you're never dependent on trusting this app's own disconnect
  button.
- **Nothing is sent to any third-party server.** The only network
  calls are to Google's own Gmail API (to read/label mail) — the
  classification itself runs locally using your trained model.
- **Minimal logging.** Only the email subject and a short snippet are
  ever written to the scan history — full email bodies are never
  stored anywhere.

## Troubleshooting

- **"Access blocked: this app's request is invalid"** — double check
  you added your own email as a Test User in Step 3.
- **"redirect_uri_mismatch"** — make sure you chose "Desktop app" (not
  "Web application") as the credential type in Step 4.
- **Nothing happens when new mail arrives** — the scanner only alerts
  on mail that arrives *after* it starts running; it intentionally
  ignores your existing inbox on first launch.
