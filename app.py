"""
app.py
------
Streamlit interface for the phishing detector.

Classification is strictly binary: PHISHING or SAFE. The old
confidence-threshold "SUSPICIOUS" middle tier has been removed to
keep the system easier to explain and defend.

Uses the Naive Bayes model (models/phishing_model.pkl) instead of
Random Forest. The rule-based "reasons" checklist (Feature Extractor)
is kept as a separate explainability layer shown alongside the verdict.
"""

import html
import json
import subprocess
import sys
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

import classifier
import storage
from classifier import classify

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"
VECTORIZER_PATH = BASE_DIR / "models" / "vectorizer.pkl"
METRICS_PATH = BASE_DIR / "models" / "metrics.json"

st.set_page_config(
    page_title="Adaptive AI Phishing Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_resource
def load_model_status():
    """Confirm the model files are present before the UI tries to
    classify anything; classification itself is handled by
    classifier.py."""
    if not MODEL_PATH.exists() or not VECTORIZER_PATH.exists():
        return False
    joblib.load(MODEL_PATH)
    joblib.load(VECTORIZER_PATH)
    return True


def load_metrics():
    try:
        with METRICS_PATH.open(encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


if not load_model_status():
    st.error("The model files are missing. Run `python3 train_model.py`, then restart the app.")
    st.stop()

metrics = load_metrics()
if metrics is None:
    st.error("Model metrics are missing. Run `python3 train_model.py`, then restart the app.")
    st.stop()

for key, default in (("messages", []), ("active_page", "Chat"), ("gmail_seen_ids", set())):
    if key not in st.session_state:
        st.session_state[key] = default

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
# Gmail OAuth callback
#
# Google redirects the browser back to the app root with ?code=... .
# This has to be handled on every page, not just Settings, otherwise a
# visitor who lands on Chat leaves the one-time code unused in the URL.
# ---------------------------------------------------------------------
def handle_oauth_redirect():
    try:
        import gmail_auth_web
    except Exception:
        return
    try:
        if not gmail_auth_web.is_cloud_configured():
            return
        if gmail_auth_web.handle_redirect_callback():
            st.rerun()
    except Exception as exc:
        st.error(f"Google login could not be completed ({exc}). Please click Connect Gmail Account again.")


handle_oauth_redirect()


def count_scans():
    rows = storage.read_scan_log()
    total = len(rows)
    phishing = sum(1 for r in rows if r["Verdict"] == "PHISHING")
    safe = sum(1 for r in rows if r["Verdict"] == "SAFE")
    return total, phishing, safe


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
        if st.button(f"{icon} {name}", key=f"nav_{name}", width="stretch"):
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
            # Escape before injecting into HTML: pasted text is untrusted.
            st.markdown(
                f'<div class="user-msg">{html.escape(str(msg["content"]))}</div>',
                unsafe_allow_html=True,
            )
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
        send_clicked = st.button("Send ➤", width="stretch")

    if send_clicked and user_text.strip():
        text = user_text.strip()
        st.session_state.messages.append({"role": "user", "content": text})

        verdict, confidence, reasons = classify(text)
        st.session_state.messages.append({
            "role": "result", "verdict": verdict,
            "confidence": confidence, "reasons": reasons,
        })
        storage.append_scan_log(text, verdict, confidence)
        st.session_state.last_scanned_text = text
        st.session_state.last_verdict = verdict
        st.session_state.feedback_given_for = None
        st.rerun()

    if st.session_state.messages and st.session_state.messages[-1]["role"] == "result":
        st.divider()
        st.caption("Was this correct?")
        feedback_key = (
            f"{st.session_state.get('last_scanned_text', '')}"
            f"|{st.session_state.get('last_verdict', '')}"
        )
        if st.session_state.get("feedback_given_for") == feedback_key:
            st.success("Thanks — your feedback has been saved.")
        else:
            c1, c2 = st.columns(2)
            if c1.button("✅ Yes, correct"):
                label = 1 if st.session_state.last_verdict == "PHISHING" else 0
                storage.append_feedback(st.session_state.last_scanned_text, label)
                st.session_state.feedback_given_for = feedback_key
                st.rerun()
            if c2.button("❌ No, incorrect"):
                label = 0 if st.session_state.last_verdict == "PHISHING" else 1
                storage.append_feedback(st.session_state.last_scanned_text, label)
                st.session_state.feedback_given_for = feedback_key
                st.info("Correction saved. Retrain the model from Settings to apply it.")
                st.rerun()

# ---------------------------------------------------------------------
# History page
# ---------------------------------------------------------------------
elif page == "History":
    st.title("📜 Scan History")
    rows = storage.read_scan_log()
    if not rows:
        st.info("No scans yet. Go to Chat to scan a message.")
    else:
        log_df = pd.DataFrame(rows)
        log_df = log_df.iloc[::-1].reset_index(drop=True)
        st.dataframe(log_df, width="stretch")

# ---------------------------------------------------------------------
# Statistics page
# ---------------------------------------------------------------------
elif page == "Statistics":
    st.title("📊 Model Accuracy & Statistics")

    total, phishing, safe = count_scans()
    feedback_given = len(storage.read_feedback())

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Scans", total)
    c2.metric("Phishing Detected", phishing)
    c3.metric("Safe Messages", safe)
    c4.metric("Feedback Given", feedback_given)

    st.divider()
    st.subheader("🎯 Model Accuracy")

    acc = float(metrics.get("accuracy", 0.0))
    prec = float(metrics.get("precision", 0.0))
    rec = float(metrics.get("recall", 0.0))
    f1 = float(metrics.get("f1_score", 0.0))
    test_size = int(metrics.get("test_size", 0))

    col_left, col_right = st.columns([1, 2])
    with col_left:
        st.metric("Overall accuracy", f"{acc * 100:.2f}%")
        st.progress(min(max(acc, 0.0), 1.0))
        correct = round(acc * test_size) if test_size else 0
        st.caption(
            f"Correctly classified **{correct} of {test_size}** held-out test messages."
        )
    with col_right:
        scores = pd.DataFrame(
            {"Score (%)": [acc * 100, prec * 100, rec * 100, f1 * 100]},
            index=["Accuracy", "Precision", "Recall", "F1-score"],
        )
        st.bar_chart(scores, height=280)
        st.caption("All four measures are shown as percentages on the same 0–100 scale.")

    st.subheader("Accuracy by class")
    cm = metrics.get("confusion_matrix", {})
    tn = int(cm.get("true_negative", 0))
    fp = int(cm.get("false_positive", 0))
    fn = int(cm.get("false_negative", 0))
    tp = int(cm.get("true_positive", 0))

    class_df = pd.DataFrame([
        {"Class": "Safe", "Correct": tn, "Total": tn + fp},
        {"Class": "Phishing", "Correct": tp, "Total": tp + fn},
    ])
    class_df["Accuracy (%)"] = (
        class_df["Correct"] / class_df["Total"].replace(0, pd.NA) * 100
    ).round(1)

    col_left, col_right = st.columns([1, 1])
    with col_left:
        st.dataframe(class_df, width="stretch", hide_index=True)
    with col_right:
        st.bar_chart(class_df.set_index("Class")["Accuracy (%)"], height=240)

    with st.expander("Confusion matrix (technical detail)"):
        st.caption(
            "Rows are the true label and columns are the model's prediction. "
            "The diagonal cells are correct decisions; off-diagonal cells are errors."
        )
        cm_df = pd.DataFrame(
            [[tn, fp], [fn, tp]],
            index=["Actually Safe", "Actually Phishing"],
            columns=["Predicted Safe", "Predicted Phishing"],
        )
        st.dataframe(cm_df, width="stretch")

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

        rescan = st.checkbox("Re-scan emails already checked in this session", value=False)

        c1, c2 = st.columns(2)
        if c1.button("🔍 Scan inbox now"):
            with st.spinner("Scanning recent inbox messages..."):
                try:
                    import gmail_scanner
                    scan_service = service or gmail.get_gmail_service()
                    seen = None if rescan else st.session_state.gmail_seen_ids
                    results = gmail_scanner.scan_recent_inbox_once(
                        service=scan_service, max_results=10, seen_ids=seen
                    )
                    flagged = [r for r in results if r["verdict"] == "PHISHING"]
                    if not results:
                        st.info("No new emails to scan.")
                    else:
                        st.info(f"Scanned {len(results)} recent emails — {len(flagged)} flagged as phishing.")
                        for r in results:
                            icon = "🚨" if r["verdict"] == "PHISHING" else "✅"
                            st.write(f'{icon} **{r["verdict"]}** ({r["confidence"]}%) — {r["subject"]}')
                except Exception as e:
                    st.error(f"Scan failed: {e}")

        if c2.button("🔌 Disconnect Gmail"):
            gmail.disconnect()
            st.session_state.gmail_seen_ids = set()
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
    st.caption(
        "Merge saved user feedback with the training data and rebuild the model. "
        f"{len(storage.read_feedback())} feedback example(s) will be used."
    )

    if st.button("🔄 Retrain Model Now"):
        with st.spinner("Retraining..."):
            try:
                result = subprocess.run(
                    [sys.executable, str(BASE_DIR / "train_model.py")],
                    capture_output=True, text=True, cwd=str(BASE_DIR), timeout=300,
                )
            except subprocess.TimeoutExpired:
                st.error("Training timed out after 5 minutes.")
            else:
                if result.returncode == 0:
                    classifier.reset_model()
                    st.cache_resource.clear()
                    st.success("Model retrained successfully. The new model is now active.")
                    st.rerun()
                else:
                    st.error(f"Error: {result.stderr or result.stdout}")

    st.divider()
    st.subheader("Data Management")
    if st.button("🗑️ Clear Scan History"):
        storage.clear_scan_log()
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
