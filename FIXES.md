# Fixes Applied — 7 November 2026

This changelog records every change made to the live version
(`Dappa-Gospel/adaptive-phishing-detector`, HEAD `4af0630`) after the duplicate
folders were consolidated into this single `phishing-detector/` directory.

The full before/after findings list is in `CODE_REVIEW.md`.

---

## 1. Project consolidation

- Compared 9 local folders, 5 zip archives and the GitHub `main` branch.
- Confirmed the GitHub repo was the newest source (deployed `app.py` hash
  `c18dbb9`, matching the 30 Aug copy, but with newer `classifier.py`,
  `gmail_auth_web.py`, dataset and models).
- Preserved the unique documents in `docs/`:
  `Project-Guide.pdf`, `Technical-Guide.pdf`, `System-Report.docx`,
  `Seminar-Defence.docx`.
- Deleted all duplicate folders and zips. A rollback archive containing every
  deleted copy was saved before deletion.
- The only surviving project folder is this one.

---

## 2. Security fixes

| Issue | Fix |
|---|---|
| Command injection through an email subject via `os.system()` | `gmail_scanner.notify_desktop()` now uses list-form `subprocess.run()` and `_applescript_escape()`; the subject is never parsed by a shell. |
| Reflected HTML injection in the chat view | Pasted text is passed through `html.escape()` before `st.markdown(..., unsafe_allow_html=True)`. |
| OAuth `state` accepted when session state was lost | `gmail_auth_web.make_state()` / `verify_state()` use an HMAC-SHA256-signed, timestamped nonce with a 600-second TTL. Verification fails closed and survives a fresh Streamlit session. |
| Secrets accidentally committable | `.gitignore` covers `credentials.json`, `gmail_token.json`, `.streamlit/secrets.toml`, `.env`, `.venv/`, `*.zip`. |

> **Action still required by the owner:** revoke the GitHub personal access
> token that was stored in plaintext in the deleted
> `Gospel_UG-22-6092/.git/config`.

---

## 3. Correctness fixes

- **Adaptive learning is now real.** `train_model.py` loads
  `data/feedback.csv`, lets user corrections override conflicting dataset
  labels, and repeats each correction three times so it is not drowned out.
- **Honest evaluation.** Punctuation/case-only near-duplicates are removed
  before the train/test split. Accuracy dropped from the previously reported
  **98.79%** to the truthful **97.47%**.
- **One decision rule.** `classifier.decide()` is the single source of truth
  for thresholds; both the app and the training script call it.
- **Empty input is SAFE 0.0%**, not a confidence-based PHISHING verdict.
- **Hyphen rule fixed.** Only phishing-style action words such as
  `account-verify-now.com` are flagged; ordinary domains such as
  `my-company.com` are not.
- **HTML-only emails are scanned.** `extract_text()` prefers `text/plain` and
  falls back to stripped HTML, with `<script>`/`<style>` content removed.
- **No duplicate inbox scans.** The Settings button passes
  `st.session_state.gmail_seen_ids`, so repeat clicks do not re-log the same
  emails and inflate statistics.
- **Positive feedback is saved** as well as negative feedback.
- **Retraining takes effect immediately.** The app calls
  `classifier.reset_model()` and clears the Streamlit model cache.
- **Absolute paths everywhere**, so the app works regardless of the launch
  directory; `logs/` and `data/` are created automatically.
- **CSV persistence centralised in `storage.py`** with headers, a thread lock,
  and backward compatibility with headerless files.
- **Dependencies pinned** in `requirements.txt`.

---

## 4. Statistics page — supervisor feedback addressed

The supervisor's comment was that the page showed a confusion matrix instead of
"the level of accuracy of the model". The page is now titled
**"Model Accuracy & Statistics"** and leads with:

1. Four headline counters: total scans, phishing detected, safe messages,
   feedback given.
2. A prominent **Overall accuracy** metric (e.g. **97.47%**) with a progress bar
   and the sentence "Correctly classified 154 of 158 held-out test messages."
3. A bar chart comparing accuracy, precision, recall and F1 on the same
   0–100% scale.
4. An **Accuracy by class** table and chart for Safe vs Phishing.
5. The confusion matrix is retained only inside a collapsed
   **"Confusion matrix (technical detail)"** expander, for anyone who wants the
   raw error breakdown.

Current model metrics (`models/metrics.json`):

| Measure | Value |
|---|---|
| Accuracy | 97.47% |
| Precision | 98.70% |
| Recall | 96.20% |
| F1-score | 97.44% |
| 5-fold CV mean | 97.59% ± 1.44% |
| Samples | 789 (631 train / 158 test) |
| Duplicates removed before split | 34 |

---

## 5. Testing

A `pytest` suite was added under `tests/`:

- `test_classifier.py` — verdicts, thresholds, empty input, hyphen regex.
- `test_storage.py` — scan log and feedback round-trips, headers, bad rows.
- `test_gmail_scanner.py` — AppleScript/shell escaping, HTML extraction.
- `test_gmail_auth_web.py` — signed OAuth state, tampering, expiry.
- `test_app_smoke.py` — all five pages render; Statistics shows overall accuracy.

Run with:

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q
```

Result: **33 passed**.
