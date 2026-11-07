# Adaptive AI-Based Phishing Detection System

A Streamlit application that classifies a message, email or URL as **PHISHING**
or **SAFE** using TF-IDF feature extraction plus a Multinomial Naive Bayes
classifier, with a rule-based explanation layer and an optional Gmail inbox
scanner.

## Features

- **Chat page** — paste any message and get a binary verdict with a confidence
  score and a plain-English list of the suspicious signals found.
- **History** — every scan is logged and shown newest-first.
- **Statistics** — model accuracy, precision, recall and F1, plus a per-class
  accuracy breakdown.
- **Settings** — connect a Gmail account (desktop flow locally, web OAuth on a
  public deployment), scan the inbox on demand, retrain from saved feedback,
  and clear the scan history.
- **About** — model card and methodology summary.
- **Adaptive retraining** — user corrections are stored in
  `data/feedback.csv` and merged into the training data when the model is
  retrained.

## Project structure

```
app.py                 Streamlit UI and page routing
classifier.py          Shared classification + explanation logic
train_model.py         Builds models/phishing_model.pkl and metrics
generate_dataset.py    Produces the synthetic training dataset
gmail_auth.py          Desktop (local) Gmail OAuth flow
gmail_auth_web.py      Web OAuth flow for public deployments
gmail_scanner.py       Inbox scanning (CLI loop + one-shot scan)
data/
  dataset.csv          Training data
  feedback.csv         User corrections (created automatically)
models/
  phishing_model.pkl   Trained classifier
  vectorizer.pkl       Fitted TF-IDF vectorizer
  metrics.json         Evaluation results shown in the app
logs/
  scan_log.csv         Scan history (created automatically)
docs/                  Project report, guides and defence material
```

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

The app opens at <http://localhost:8501>.

## Retrain the model

```bash
python3 train_model.py
```

This rebuilds `models/phishing_model.pkl`, `models/vectorizer.pkl` and
`models/metrics.json` from `data/dataset.csv` **and** `data/feedback.csv`.

## Tests

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q
```

## Gmail integration

See `SETUP_GUIDE.md` for the local desktop flow and
`CLOUD_DEPLOYMENT_GUIDE.md` for the public web-OAuth flow.

The Gmail scope is `gmail.modify`: the app can read mail and apply a label, but
it cannot send mail or permanently delete anything. Tokens are never committed;
`.gitignore` excludes `credentials.json`, `gmail_token.json` and
`.streamlit/secrets.toml`.

## Data and privacy

- Only the subject line and a short snippet are written to the scan log.
- Feedback is stored as text plus the corrected label.
- No third-party server is contacted; the only external calls are to Google's
  own Gmail API when the inbox feature is used.

## Known limitations

- The training data is synthetic and template-generated; accuracy on real-world
  mail is lower than the in-dataset score.
- The Gmail integration is optional and requires your own Google Cloud OAuth
  credentials.
- This is a decision-support tool. It never blocks, deletes or sends email on
  its own.
