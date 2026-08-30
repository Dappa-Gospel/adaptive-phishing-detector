"""
app.py
------
Streamlit interface for the phishing detector.

Simplified from the original version:
- Classification is now strictly binary: PHISHING or SAFE. The old
  confidence-threshold "SUSPICIOUS" middle tier has been removed to
  keep the system easier to explain and defend.
- Uses the Naive Bayes model (models/phishing_model.pkl) instead of
  Random Forest.
- The rule-based "reasons" checklist (Feature Extractor) is kept as
  a separate explainability layer shown alongside the verdict - it
  does not influence the model's decision, it just helps the user
  understand WHY a message looks suspicious.
"""

import csv
import json
import os
from datetime import datetime

import joblib
import pandas as pd
import streamlit as st

from classifier import classify

MODEL_PATH = "models/phishing_model.pkl"
VECTORIZER_PATH = "models/vectorizer.pkl"
METRICS_PATH = "models/metrics.json"
LOG_PATH = "logs/scan_log.csv"
FEEDBACK_PATH = "data/feedback.csv"
DATA_PATH = "data/dataset.csv"

st.set_page_config(
    page_title="Adaptive AI Phishing Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_resource
def load_model_status():
    """Just used to confirm the model files are present before the
    Chat page tries to classify anything; classification itself is
    handled by classifier.py."""
    joblib.load(MODEL_PATH)
    joblib.load(VECTORIZER_PATH)
    return True


def load_metrics():
    with open(METRICS_PATH) as f:
        return json.load(f)


load_model_status()
metrics = load_metrics()

if "messages" not in st.session_state:
    st.session_state.messages = []
if "active_page" not in st.session_state:
    st.session_state.active_page = "Chat"
if "feedback_count" not in st.session_state:
    st.session_state.feedback_count = 0

st.markdown(
    """
    <style>
    .stApp { background-color: #0f1117; color: #e6e6e6; }
    .user-msg { background: #2d3561; border-radius: 18px; padding: 10px 16px; margin: 6px 0; }
    .bot-msg.phishing { border-left: 4px solid #ff4d6d; padding: 10px 16px; background: #1a1c25; border-radius: 8px; }
    .bot-msg.safe { border-left: 4px solid #00d4aa; padding: 10px 16px; background: #1a1c25; border-radius: 8px; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------
# Core classification logic now lives in classifier.py (shared with
# gmail_scanner.py) - imported at the top of this file.
# ---------------------------------------------------------------------


def log_scan(text, verdict, confidence):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now(), text[:80], verdict, confidence])


def save_feedback(text, correct_label):
    with open(FEEDBACK_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([text, correct_label])
    st.session_state.feedback_count += 1


def count_scans():
    try:
        log_df = pd.read_csv(LOG_PATH, header=None,
                              names=["Timestamp", "Message", "Verdict", "Confidence"])
        total = len(log_df)
        phishing = (log_df["Verdict"] == "PHISHING").sum()
        safe = (log_df["Verdict"] == "SAFE").sum()
        return total, phishing, safe
    except (FileNotFoundError, pd.errors.EmptyDataError):
        return 0, 0, 0


# ---------------------------------------------------------------------
# Sidebar navigation
# ---------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🛡️ Phishing Detector")
    st.caption("Adaptive AI-Based Detection System")
    st.divider()
    pages = [("💬", "Chat"), ("📜", "History"), ("📊", "Statistics"),
             ("⚙️", "Settings"), ("ℹ️", "About")]
    for icon, name in pages:
        if st.button(f"{icon} {name}", key=f"nav_{name}", use_container_width=True):
            st.session_state.active_page = name
            st.rerun()
    st.divider()
    st.caption(f"Model: Naive Bayes · Accuracy: {metrics['accuracy']*100:.1f}%")


page = st.session_state.active_page

# ---------------------------------------------------------------------
# Chat page
# ---------------------------------------------------------------------
if page == "Chat":
    st.title("💬 Scan a Message")
    st.caption("Paste any suspicious message, email, or URL below.")

    for msg in st.session_state.messages:
        if msg["role"] == "user":
            st.markdown(f'<div class="user-msg">{msg["content"]}</div>', unsafe_allow_html=True)
        elif msg["role"] == "result":
            css_class = "phishing" if msg["verdict"] == "PHISHING" else "safe"
            icon = "🚨" if msg["verdict"] == "PHISHING" else "✅"
            st.markdown(
                f'<div class="bot-msg {css_class}"><b>{icon} {msg["verdict"]}</b> '
                f'(confidence: {msg["confidence"]}%)</div>',
                unsafe_allow_html=True,
            )
            if msg["reasons"]:
                for r in msg["reasons"]:
                    st.markdown(f"- {r}")

    col_input, col_send = st.columns([5, 1])
    with col_input:
        user_text = st.text_area("Message", label_visibility="collapsed",
                                  placeholder="Type or paste a message, email, or URL...",
                                  height=80)
    with col_send:
        send_clicked = st.button("Send ➤", use_container_width=True)

    if send_clicked and user_text.strip():
        text = user_text.strip()
        st.session_state.messages.append({"role": "user", "content": text})

        verdict, confidence, reasons = classify(text)
        st.session_state.messages.append({
            "role": "result", "verdict": verdict,
            "confidence": confidence, "reasons": reasons,
        })
        log_scan(text, verdict, confidence)
        st.session_state.last_scanned_text = text
        st.session_state.last_verdict = verdict
        st.rerun()

    if st.session_state.messages and st.session_state.messages[-1]["role"] == "result":
        st.divider()
        st.caption("Was this correct?")
        c1, c2 = st.columns(2)
        if c1.button("✅ Yes, correct"):
            st.success("Thanks for confirming!")
        if c2.button("❌ No, incorrect"):
            correct_label = 0 if st.session_state.last_verdict == "PHISHING" else 1
            save_feedback(st.session_state.last_scanned_text, correct_label)
            st.info("Correction saved. Retrain the model from Settings to apply it.")

# ---------------------------------------------------------------------
# History page
# ---------------------------------------------------------------------
elif page == "History":
    st.title("📜 Scan History")
    try:
        log_df = pd.read_csv(LOG_PATH, header=None,
                              names=["Timestamp", "Message", "Verdict", "Confidence"])
        log_df = log_df.iloc[::-1].reset_index(drop=True)
        st.dataframe(log_df, use_container_width=True)
    except (FileNotFoundError, pd.errors.EmptyDataError):
        st.info("No scans yet. Go to Chat to scan a message.")

# ---------------------------------------------------------------------
# Statistics page
# ---------------------------------------------------------------------
elif page == "Statistics":
    st.title("📊 Statistics")
    total, phishing, safe = count_scans()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Scans", total)
    c2.metric("Phishing Detected", phishing)
    c3.metric("Safe Messages", safe)
    c4.metric("Feedback Given", st.session_state.feedback_count)

    st.divider()
    st.subheader("Model Performance")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Accuracy", f"{metrics['accuracy']*100:.1f}%")
    c2.metric("Precision", f"{metrics['precision']*100:.1f}%")
    c3.metric("Recall", f"{metrics['recall']*100:.1f}%")
    c4.metric("F1-Score", f"{metrics['f1_score']*100:.1f}%")

    st.subheader("Confusion Matrix")
    cm = metrics["confusion_matrix"]
    cm_df = pd.DataFrame(
        [[cm["true_negative"], cm["false_positive"]],
         [cm["false_negative"], cm["true_positive"]]],
        index=["Actually Safe", "Actually Phishing"],
        columns=["Predicted Safe", "Predicted Phishing"],
    )
    st.dataframe(cm_df, use_container_width=True)

# ---------------------------------------------------------------------
# Settings page
# ---------------------------------------------------------------------
elif page == "Settings":
    st.title("⚙️ Settings")

    st.subheader("📧 Gmail Integration")
    import gmail_auth
    import gmail_auth_web

    CLOUD_MODE = gmail_auth_web.is_cloud_configured()
    gmail = gmail_auth_web if CLOUD_MODE else gmail_auth

    if CLOUD_MODE:
        # Complete the login exchange if Google just redirected back
        # with a ?code=... parameter in the URL.
        gmail_auth_web.handle_redirect_callback()
        st.caption("🌐 Running in public deployment mode — each visitor connects their own account for their session only.")

    if gmail.is_connected():
        try:
            service = gmail.get_gmail_service()
            email = gmail.get_connected_email(service)
            st.success(f"Connected as **{email}**")
        except Exception as e:
            st.warning(f"Connected, but couldn't verify the account right now ({e}). "
                       "Try reconnecting if this persists.")
            service = None

        c1, c2 = st.columns(2)
        if c1.button("🔍 Scan inbox now"):
            with st.spinner("Scanning recent inbox messages..."):
                try:
                    import gmail_scanner
                    scan_service = service or gmail.get_gmail_service()
                    results = gmail_scanner.scan_recent_inbox_once(service=scan_service, max_results=10)
                    flagged = [r for r in results if r["verdict"] == "PHISHING"]
                    st.info(f"Scanned {len(results)} recent emails — {len(flagged)} flagged as phishing.")
                    for r in results:
                        icon = "🚨" if r["verdict"] == "PHISHING" else "✅"
                        st.write(f'{icon} **{r["verdict"]}** ({r["confidence"]}%) — {r["subject"]}')
                except Exception as e:
                    st.error(f"Scan failed: {e}")

        if c2.button("🔌 Disconnect Gmail"):
            gmail.disconnect()
            st.success("Disconnected.")
            st.rerun()

        if not CLOUD_MODE:
            st.caption(
                "For continuous background monitoring instead of manual scans, "
                "run `python3 gmail_scanner.py` in a terminal — it checks your "
                "inbox every 30 seconds while running."
            )
        else:
            st.caption("Your session's Gmail access is held in memory only and is discarded when you close this tab.")
    else:
        st.write("Connect your Gmail account so incoming emails can be scanned automatically.")

        if CLOUD_MODE:
            auth_url = gmail_auth_web.get_authorization_url()
            st.link_button("🔗 Connect Gmail Account", auth_url)
        else:
            if st.button("🔗 Connect Gmail Account"):
                with st.spinner("Opening browser for Google sign-in..."):
                    try:
                        email = gmail_auth.connect()
                        st.success(f"Connected as **{email}**!")
                        st.rerun()
                    except FileNotFoundError as e:
                        st.error(str(e))
                    except Exception as e:
                        st.error(f"Connection failed: {e}")

        with st.expander("🔒 How your data is kept safe"):
            st.markdown("""
            - **Your Gmail password is never seen or stored by this app.**
              Login happens entirely on Google's own page; this app only
              receives a limited access token afterward.
            - **Limited permission scope.** This app can only read your
              email and apply labels — it **cannot send email or
              permanently delete anything** from your account.
            - **You can disconnect anytime** with the button above, or
              independently revoke access at
              [myaccount.google.com/permissions](https://myaccount.google.com/permissions)
              — you don't have to trust this app's own disconnect button.
            - **Minimal logging.** Only the subject line and a short
              snippet are ever saved to the scan history — full email
              bodies are never stored.
            """ + ("""
            - **Public deployment note:** your Gmail access is stored only
              in this browser session's memory on the server, never written
              to disk, and is automatically discarded the moment you close
              this tab or disconnect. No other visitor to this site can see
              your account or data.
            """ if CLOUD_MODE else """
            - **Nothing leaves your machine** except the direct connection
              to Google's own Gmail API — no third-party server is involved.
            """))

        if not CLOUD_MODE:
            st.caption("First-time setup required — see SETUP_GUIDE.md for Google Cloud steps.")

    st.divider()
    st.subheader("Adaptive Retraining")
    st.caption("Merge saved user feedback with the training data and rebuild the model.")

    if st.button("🔄 Retrain Model Now"):
        with st.spinner("Retraining..."):
            import subprocess
            result = subprocess.run(["python3", "train_model.py"],
                                     capture_output=True, text=True)
            if result.returncode == 0:
                st.success("Model retrained successfully! Restart the app to load the new model.")
            else:
                st.error(f"Error: {result.stderr}")

    st.divider()
    st.subheader("Data Management")
    if st.button("🗑️ Clear Scan History"):
        open(LOG_PATH, "w").close()
        st.success("Scan history cleared.")

# ---------------------------------------------------------------------
# About page
# ---------------------------------------------------------------------
elif page == "About":
    st.title("ℹ️ About This Project")
    st.markdown(f"""
    **Adaptive AI-Based Phishing Detection System**

    A binary text classifier that detects phishing messages and URLs
    using TF-IDF feature extraction and a Multinomial Naive Bayes
    classifier, with adaptive learning from user feedback.

    - **Algorithm:** Naive Bayes
    - **Feature extraction:** TF-IDF (unigrams + bigrams)
    - **Classification:** Binary (PHISHING / SAFE)
    - **Accuracy:** {metrics['accuracy']*100:.1f}%
    - **Precision:** {metrics['precision']*100:.1f}%
    - **Recall:** {metrics['recall']*100:.1f}%
    - **Training samples:** {metrics['total_samples']}
    """)
