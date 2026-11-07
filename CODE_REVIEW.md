# Code Review — Adaptive Phishing Detection System (LIVE / up-to-date)

Source of truth: GitHub `Dappa-Gospel/adaptive-phishing-detector`, branch `main`,
HEAD `4af0630` (2026-09-06). This is the code Streamlit Community Cloud deploys.
Cloned locally to `phishing-detector/` — the single surviving copy.

All local folders (`Gospel_UG-22-6092`, `Dappa_UG-22-6092`, etc.) stopped at the
30 Aug "Final year project submission" commit and were **stale**; they have been
deleted after a backup was taken.

Status legend: ✅ fixed · ⚠️ still present · 🆕 new in live.

> **Status after remediation (7 Nov 2026): every finding below is fixed.**
> See `FIXES.md` for the change list and the test suite in `tests/`.

---

## Inventory (what was compared)

| Location | app.py hash | Date | Note |
|---|---|---|---|
| `Documents/Adaptive Phising AI` (+3 copies) | `233e7c6` | 23 May | Old design: `SUSPICIOUS` tier, single file, no Gmail |
| `Downloads/Adaptive-Phishing-System` | `7b0b113` | 28 Aug 06:51 | Rewrite, no Gmail |
| `Downloads/Final year project` | `1f7081d` | 28 Aug 07:22 | Intermediate |
| `Downloads/Adaptive-Phishing-System-Email` | `1a9844a` | 28 Aug 20:56 | **Incomplete** — `gmail_scanner` imports missing `gmail_auth` |
| `Downloads/Dappa_UG-22-6092` | `2b04bfa` | 28 Aug 21:50 | Complete local Gmail flow |
| `Downloads/Gospel_UG-22-6092` | `c18dbb9` | 30 Aug 06:53 | Final submission + public OAuth |
| **GitHub `main`** | `c18dbb9` | **06 Sep** | Same `app.py`, but newer `classifier.py`, `gmail_auth_web.py`, dataset, models |

Zips are snapshots of the above; `Gospel_UG-22-6092.zip` is the newest zip but
still stops at 30 Aug.

---

## What the live version already fixed

- ✅ **Empty/blank input no longer returns PHISHING.** `classifier.py` now
  requires an 80% ML score when there are no rule hits, and treats empty text
  as SAFE. (`classify("")` → SAFE 50.0%.)
- ✅ **Fallback reason fixed.** `analyze_reasons(..., include_fallback=False)`
  lets `classify()` distinguish "no real red flags" from "matched phishing
  language", so the filler reason is no longer used to justify a verdict.
- ✅ **OAuth robustness improved.** `gmail_auth_web.py` disables PKCE (correct
  for a confidential client across a browser redirect), guards against
  re-submitting a one-time `code`, and wraps token exchange in try/except.
- ✅ **Duplicate scans partially addressed?** No — the button path is unchanged
  (see M1).

---

## Findings and resolution (originally "still present in the live version")

### ✅ C1 (Critical) — Command injection via email subject
`gmail_scanner.py` used `os.system()` with the raw subject interpolated into the
command, allowing arbitrary command execution. **Fixed:** list-form
`subprocess.run()` plus `_applescript_escape()` for the macOS notification.

### ✅ H1 (High) — "Adaptive learning" was not implemented
`train_model.py` never read `data/feedback.csv`. **Fixed:** feedback is loaded
through `storage.read_feedback()`, overrides conflicting dataset rows, and is
weighted ×3 before the split.

### ✅ H2 (High) — OAuth `state` check failed open
`gmail_auth_web.py` skipped validation when session state was lost.
**Fixed:** HMAC-SHA256-signed, timestamped state with a 600 s TTL; verification
fails closed and survives a fresh Streamlit session.

### ✅ H3 (High) — Train/test leakage
34 punctuation/case-only duplicates leaked across the split. **Fixed:**
near-duplicates are collapsed before splitting. Honest accuracy is now
**97.47%** (previously reported 98.79%).

### ✅ M1 — "Scan inbox now" re-scanned and re-logged the same emails
**Fixed:** `gmail_scanner.scan_recent_inbox_once(..., seen_ids=...)` plus
`st.session_state.gmail_seen_ids` prevents duplicate rows.

### ✅ M3 — Reflected HTML injection in chat
**Fixed:** pasted text is passed through `html.escape()` before
`st.markdown(..., unsafe_allow_html=True)`.

### ✅ M4 — OAuth callback only ran on the Settings page
**Fixed:** `handle_oauth_redirect()` runs on every page load.

### ✅ M5 — Dependencies unpinned
**Fixed:** `requirements.txt` pins Streamlit and scikit-learn and bounds the rest.

### ✅ M6/M7 — CSV logging fragility; HTML-only emails ignored
**Fixed:** all CSV I/O goes through `storage.py` (headers, directory creation,
thread lock, headerless compatibility). `extract_text()` prefers text/plain and
falls back to stripped HTML.

### ✅ Low items
Positive feedback is now saved, feedback counts come from storage, the decision
rule lives only in `classifier.decide()`, the hyphen regex only flags
phishing-style action words, all paths are absolute, `include_granted_scopes=True`,
retraining uses `sys.executable`, `width="stretch"` replaces the deprecated
`use_container_width`, and there is a 33-test pytest suite.

---

## New problems introduced on 6 Sep

### ✅ 🆕1 (High) — The uploaded new model was not the one the app loaded
`app.py` loads `models/*.pkl`, but newer duplicate pickles were added at the
repo root. **Fixed:** the root duplicates were deleted and `models/` is the only
canonical location; the pair was retrained from the current code.

### ✅ 🆕2 (Medium) — Metrics no longer matched the code
`train_model.py` used different thresholds from `classifier.py`. **Fixed:**
offline evaluation imports `classifier.decide()`, so reported metrics describe
the rule the app actually runs.

### ✅ 🆕3 (Low) — Duplicated `metrics.json`
**Fixed:** root copy deleted; only `models/metrics.json` remains.

---

## Recommended fix order (live version)

All items below were completed; the order was followed.

1. ✅ C1 — replace `os.system` with list-form `subprocess`.
2. ✅ H1 — actually merge `data/feedback.csv` in `train_model.py`.
3. ✅ H2 — make the OAuth state check fail closed.
4. ✅ 🆕1 — decide which model pair is canonical and remove the other.
5. ✅ H3 — de-duplicate before splitting and report honest metrics.
6. ✅ 🆕2 — make `train_model.py` use the same thresholds as `classifier.py`.
7. ✅ M1, M3, M4, M5.
8. ✅ Low items.

---

## Outside the code

- The stale `.git/config` in the deleted `Downloads/Gospel_UG-22-6092` contained
  a plaintext GitHub token. That folder was removed, but **the token must still
  be revoked** on GitHub. The clean clone in `phishing-detector/` does not
  contain it.
