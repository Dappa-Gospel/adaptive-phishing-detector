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
"""

import json
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
)

DATA_PATH = "data/dataset.csv"

# Direct credential-harvesting keywords. A message that explicitly asks
# for a password, PIN, card number, etc. is almost never legitimate to
# send over chat/email, so the hybrid decision (mirrored in app.py)
# lowers the ML probability threshold needed to flag these as
# phishing, rather than requiring the bag-of-words model to be
# independently confident from word frequency alone - which is
# unreliable on short messages.
CREDENTIAL_KEYWORDS = ["password", "pin", "cvv", "otp", "one-time password",
                        "card number", "account number", "routing number",
                        "social security", "login and password", "ssn"]

def hybrid_predict(texts, phishing_probs):
    """Apply the same rule-assisted threshold used in app.py so the
    metrics reported here match what the deployed app actually does."""
    preds = []
    for text, p in zip(texts, phishing_probs):
        has_cred = any(k in text.lower() for k in CREDENTIAL_KEYWORDS)
        threshold = 0.30 if has_cred else 0.50
        preds.append(1 if p >= threshold else 0)
    return preds

# Step 1: Load the dataset
df = pd.read_csv(DATA_PATH)
print(f"Loaded {len(df)} samples")

# Step 2: Convert text to numbers with TF-IDF
vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=3000,
    sublinear_tf=True,
)
X = vectorizer.fit_transform(df["text"])
y = df["label"]

# Step 3: Split into training (80%) and testing (20%) sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Step 4: Train the Naive Bayes model
model = MultinomialNB(alpha=1.0)
model.fit(X_train, y_train)

# Step 5: Evaluate on the held-out test set using the same hybrid
# rule-assisted decision the app uses (not just the raw model)
test_texts = df.loc[y_test.index, "text"].tolist()
test_probs = model.predict_proba(X_test)[:, 1]
y_pred = hybrid_predict(test_texts, test_probs)

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)

# Step 6: 5-fold cross-validation for a more reliable estimate
cv_scores = cross_val_score(model, X, y, cv=5, scoring="accuracy")

metrics = {
    "algorithm": "Multinomial Naive Bayes + rule-assisted threshold (hybrid)",
    "accuracy": round(acc, 4),
    "precision": round(prec, 4),
    "recall": round(rec, 4),
    "f1_score": round(f1, 4),
    "cv_mean": round(cv_scores.mean(), 4),
    "cv_std": round(cv_scores.std(), 4),
    "confusion_matrix": {
        "true_negative": int(cm[0][0]),
        "false_positive": int(cm[0][1]),
        "false_negative": int(cm[1][0]),
        "true_positive": int(cm[1][1]),
    },
    "train_size": X_train.shape[0],
    "test_size": X_test.shape[0],
    "total_samples": len(df),
}

print(json.dumps(metrics, indent=2))

# Step 7: Save the model, vectorizer, and metrics
joblib.dump(model, "models/phishing_model.pkl")
joblib.dump(vectorizer, "models/vectorizer.pkl")
with open("models/metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)

print("\nSaved model, vectorizer, and metrics to models/")
