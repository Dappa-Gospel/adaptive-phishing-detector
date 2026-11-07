"""
train_model.py
----------------
Trains the phishing detector using a Multinomial Naive Bayes classifier.

Why Naive Bayes instead of Random Forest:
- It is the classic, most-cited baseline algorithm for text
  classification problems like spam and phishing detection in the
  literature (it's the same family of algorithm used in early spam
  filters). It fits a simple project much better than an ensemble
  of 200 trees.
- It is fast to train, easy to explain in one paragraph (Bayes'
  theorem: given the words in a message, what is the probability it
  belongs to each class?), and needs no hyperparameter tuning like
  tree depth or number of estimators.
- It pairs naturally with TF-IDF/word-frequency style features,
  which is exactly what this project already uses.
- Output is strictly binary: PHISHING or SAFE. No confidence-based
  "suspicious" middle tier — simpler to reason about and defend.

Adaptive learning:
- User corrections from data/feedback.csv are merged into the
  training data before the split. Corrections replace any conflicting
  dataset row for the same message, and are repeated FEEDBACK_WEIGHT
  times so a handful of corrections are not drowned out by the
  synthetic data.

Evaluation honesty:
- Near-duplicate messages (same text apart from punctuation/case) are
  collapsed before the train/test split. The old pipeline put
  punctuation-only variants of the same sentence in both sets, which
  inflated the reported accuracy.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.naive_bayes import MultinomialNB

from classifier import decide
import storage

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "dataset.csv"
MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"
VECTORIZER_PATH = BASE_DIR / "models" / "vectorizer.pkl"
METRICS_PATH = BASE_DIR / "models" / "metrics.json"

FEEDBACK_WEIGHT = 3  # how many times a user correction is repeated


def normalize_text(text: str) -> str:
    """Case/punctuation-insensitive key used only for de-duplication."""
    return re.sub(r"[^a-z0-9 ]", "", str(text).lower()).strip()


def load_training_frame() -> tuple[pd.DataFrame, int, int]:
    """Load dataset + feedback, let feedback win, and collapse
    near-duplicates. Returns (frame, feedback_count, removed_count)."""
    df = pd.read_csv(DATA_PATH)
    df["text"] = df["text"].astype(str).str.strip()
    df = df[df["text"] != ""]
    original_count = len(df)

    feedback_rows = storage.read_feedback()
    if feedback_rows:
        fb = pd.DataFrame(feedback_rows)
        fb["text"] = fb["text"].astype(str).str.strip()
        fb = fb[fb["text"] != ""]
        # User corrections override the synthetic label for the same text.
        fb_keys = set(fb["text"].map(normalize_text))
        df = df[~df["text"].map(normalize_text).isin(fb_keys)]
        # Repeat corrections so they carry real weight in training.
        fb = pd.concat([fb] * FEEDBACK_WEIGHT, ignore_index=True)
        df = pd.concat([df, fb], ignore_index=True)

    # Collapse punctuation/case variants that would otherwise leak
    # across the train/test boundary.
    df["_key"] = df["text"].map(normalize_text)
    df = df[~df["_key"].duplicated(keep="first")].drop(columns="_key")
    df = df.reset_index(drop=True)

    removed = original_count + (len(feedback_rows) * FEEDBACK_WEIGHT) - len(df)
    return df, len(feedback_rows), max(removed, 0)


def build_model(X_train, y_train):
    model = MultinomialNB(alpha=1.0)
    model.fit(X_train, y_train)
    return model


def hybrid_predictions(texts, phishing_probs):
    return [1 if decide(p, text)[0] else 0 for text, p in zip(texts, phishing_probs)]


def main() -> None:
    df, feedback_count, removed = load_training_frame()
    print(f"Loaded {len(df)} samples "
          f"({(df['label'] == 1).sum()} phishing, {(df['label'] == 0).sum()} legitimate)")
    print(f"Feedback rows merged: {feedback_count} (weight x{FEEDBACK_WEIGHT})")
    print(f"Near-duplicates removed before split: {removed}")

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=3000,
        sublinear_tf=True,
    )
    X = vectorizer.fit_transform(df["text"])
    y = df["label"].to_numpy()
    texts = df["text"].tolist()

    X_train, X_test, y_train, y_test, text_train, text_test = train_test_split(
        X, y, texts,
        test_size=0.2, random_state=42, stratify=y,
    )

    model = build_model(X_train, y_train)

    # Evaluate with the same hybrid rule the app uses.
    test_probs = model.predict_proba(X_test)[:, 1]
    y_pred = hybrid_predictions(text_test, test_probs)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    # Cross-validation of the full hybrid pipeline, not just the raw
    # model, so cv_mean describes the deployed behaviour.
    cv_scores = []
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for train_idx, test_idx in skf.split(X, y):
        fold_model = build_model(X[train_idx], y[train_idx])
        fold_probs = fold_model.predict_proba(X[test_idx])[:, 1]
        fold_texts = [texts[i] for i in test_idx]
        fold_pred = hybrid_predictions(fold_texts, fold_probs)
        cv_scores.append(accuracy_score(y[test_idx], fold_pred))
    cv_scores = pd.Series(cv_scores)

    safe_total = tn + fp
    phish_total = tp + fn
    per_class_accuracy = {
        "safe": round(tn / safe_total, 4) if safe_total else 0.0,
        "phishing": round(tp / phish_total, 4) if phish_total else 0.0,
    }

    metrics = {
        "algorithm": "Multinomial Naive Bayes + rule-assisted threshold (hybrid)",
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "cv_mean": round(float(cv_scores.mean()), 4),
        "cv_std": round(float(cv_scores.std()), 4),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
        "per_class_accuracy": per_class_accuracy,
        "train_size": int(X_train.shape[0]),
        "test_size": int(X_test.shape[0]),
        "total_samples": int(len(df)),
        "feedback_samples": int(feedback_count),
        "duplicates_removed": int(removed),
    }

    print(json.dumps(metrics, indent=2))

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    with METRICS_PATH.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("\nSaved model, vectorizer and metrics to models/")


if __name__ == "__main__":
    main()
