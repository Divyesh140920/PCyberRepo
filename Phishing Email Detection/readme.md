# Phishing Email Detection

A machine-learning classifier that flags phishing emails. It combines TF-IDF
text features with two hand-engineered signals (URL count and
phishing-keyword count) and trains a Random Forest.

## Setup

```bash
pip install -r requirements.txt
```

NLTK stopwords download automatically on first run.

## Dataset

A CSV with two columns:

| column | meaning |
|--------|---------|
| `email_text` | the raw email body |
| `label` | `1` = phishing, `0` = legitimate |

Public corpora you can use include the Enron-based phishing sets and the
SpamAssassin public corpus.

## Usage

```bash
# Train (saves phishing_model.pkl and tfidf_vectorizer.pkl)
python phishing_email_detector.py train --dataset emails.csv

# Classify new messages
python phishing_email_detector.py predict --text "Urgent: verify your account now"
python phishing_email_detector.py predict --file suspicious.txt
```

## What changed in this rewrite

- **Separate `train` and `predict` commands** — you can score new emails with
  the saved model instead of retraining every run.
- **Fixed the feature matrix** — TF-IDF and numeric features are now combined
  as a sparse matrix (`scipy.hstack`), avoiding the dense-DataFrame column
  collision and memory blow-up in the original.
- **Prediction confidence** is reported via `predict_proba`.
- **Lazy, guarded NLTK download** and clear errors for a missing or
  malformed dataset.
- **Stratified train/test split** so class balance is preserved.
