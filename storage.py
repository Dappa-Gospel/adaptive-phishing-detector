"""
storage.py
----------
Single place that reads and writes the two CSV files the app owns:

  logs/scan_log.csv   every scan result shown in History/Statistics
  data/feedback.csv   user corrections used by adaptive retraining

Centralising this avoids three classes of bug the old code had:
- a fresh deployment writing data rows with no header,
- `logs/` not existing when the scanner wrote to it,
- two Streamlit sessions interleaving rows in the same file.

All paths are derived from this file's location, so the app works no
matter which directory it is launched from.
"""

from __future__ import annotations

import csv
import threading
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

LOG_PATH = BASE_DIR / "logs" / "scan_log.csv"
FEEDBACK_PATH = BASE_DIR / "data" / "feedback.csv"

LOG_HEADER = ["Timestamp", "Message", "Verdict", "Confidence"]
FEEDBACK_HEADER = ["text", "label"]

_lock = threading.Lock()


def _prepare(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _needs_header(path: Path) -> bool:
    return not path.exists() or path.stat().st_size == 0


def append_scan_log(text: str, verdict: str, confidence: float) -> None:
    with _lock:
        _prepare(LOG_PATH)
        with LOG_PATH.open("a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if _needs_header(LOG_PATH):
                writer.writerow(LOG_HEADER)
            writer.writerow([
                datetime.now().isoformat(timespec="seconds"),
                str(text)[:80],
                verdict,
                confidence,
            ])


def read_scan_log() -> list[dict]:
    """Return scan rows as dicts. Handles both the current header format
    and headerless files written by older versions."""
    if not LOG_PATH.exists() or LOG_PATH.stat().st_size == 0:
        return []
    with _lock, LOG_PATH.open(newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if not rows:
        return []
    if rows[0] and rows[0][0].strip().lower() == "timestamp":
        rows = rows[1:]
    out = []
    for row in rows:
        if len(row) < 4:
            continue
        out.append({
            "Timestamp": row[0],
            "Message": row[1],
            "Verdict": row[2],
            "Confidence": row[3],
        })
    return out


def clear_scan_log() -> None:
    with _lock:
        _prepare(LOG_PATH)
        LOG_PATH.write_text("", encoding="utf-8")


def append_feedback(text: str, correct_label: int) -> None:
    if int(correct_label) not in (0, 1):
        raise ValueError("correct_label must be 0 (safe) or 1 (phishing)")
    with _lock:
        _prepare(FEEDBACK_PATH)
        with FEEDBACK_PATH.open("a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if _needs_header(FEEDBACK_PATH):
                writer.writerow(FEEDBACK_HEADER)
            writer.writerow([text, int(correct_label)])


def read_feedback() -> list[dict]:
    """Return validated feedback rows. Bad rows are skipped rather than
    crashing training."""
    if not FEEDBACK_PATH.exists() or FEEDBACK_PATH.stat().st_size == 0:
        return []
    with _lock, FEEDBACK_PATH.open(newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if not rows:
        return []
    if rows[0] and rows[0][0].strip().lower() == "text":
        rows = rows[1:]
    out = []
    for row in rows:
        if len(row) < 2 or not row[0].strip():
            continue
        try:
            label = int(float(row[1]))
        except (TypeError, ValueError):
            continue
        if label not in (0, 1):
            continue
        out.append({"text": row[0].strip(), "label": label})
    return out
