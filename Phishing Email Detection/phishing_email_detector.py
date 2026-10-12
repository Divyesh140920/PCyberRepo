"""Phishing email detector (TF-IDF + Random Forest).

Trains a classifier on a labelled corpus of emails and can then score new
messages. Combines TF-IDF text features with a couple of hand-engineered
signals (URL count, phishing-keyword count).

Dataset format (CSV): columns ``email_text`` and ``label`` where label is
1 = phishing, 0 = legitimate.

Usage:
    python phishing_email_detector.py train --dataset emails.csv
    python phishing_email_detector.py predict --text "Verify your account now!"
    python phishing_email_detector.py predict --file suspicious.txt
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

MODEL_PATH = Path("phishing_model.pkl")
VECTORIZER_PATH = Path("tfidf_vectorizer.pkl")

PHISHING_KEYWORDS = (
    "urgent", "password", "verify", "account", "click", "login",
    "bank", "update", "suspended", "confirm", "ssn", "wire",
)

_STOPWORDS: set[str] | None = None


def _stopwords() -> set[str]:
    """Lazily load NLTK stopwords, downloading them once if needed."""
    global _STOPWORDS
    if _STOPWORDS is None:
        import nltk
        try:
            from nltk.corpus import stopwords
            _STOPWORDS = set(stopwords.words("english"))
        except LookupError:
            nltk.download("stopwords", quiet=True)
            from nltk.corpus import stopwords
            _STOPWORDS = set(stopwords.words("english"))
    return _STOPWORDS


def count_urls(text: str) -> int:
    return len(re.findall(r"https?://", text, flags=re.IGNORECASE))


def count_keywords(text: str) -> int:
    low = text.lower()
    return sum(low.count(word) for word in PHISHING_KEYWORDS)


def preprocess_text(text: str) -> str:
    text = re.sub(r"[^a-zA-Z\s]", "", text).lower()
    return " ".join(word for word in text.split() if word not in _stopwords())


def _features(texts, vectorizer, fit: bool):
    import numpy as np
    from scipy.sparse import hstack, csr_matrix

    cleaned = [preprocess_text(t) for t in texts]
    tfidf = vectorizer.fit_transform(cleaned) if fit else vectorizer.transform(cleaned)
    extra = csr_matrix(
        np.array([[count_urls(t), count_keywords(t)] for t in texts], dtype=float)
    )
    return hstack([tfidf, extra]).tocsr()


def train(dataset_path: str) -> int:
    import joblib
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics import accuracy_score, classification_report
    from sklearn.model_selection import train_test_split

    try:
        df = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print(f"error: dataset not found: {dataset_path}", file=sys.stderr)
        return 1

    missing = {"email_text", "label"} - set(df.columns)
    if missing:
        print(f"error: dataset is missing column(s): {', '.join(sorted(missing))}", file=sys.stderr)
        return 1

    vectorizer = TfidfVectorizer(max_features=3000)
    X = _features(df["email_text"].astype(str).tolist(), vectorizer, fit=True)
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if y.nunique() > 1 else None
    )
    model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.3f}\n")
    print(classification_report(y_test, y_pred))

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"Saved model to {MODEL_PATH} and vectorizer to {VECTORIZER_PATH}")
    return 0


def predict(text: str) -> int:
    import joblib

    if not (MODEL_PATH.exists() and VECTORIZER_PATH.exists()):
        print("error: no trained model found — run 'train' first.", file=sys.stderr)
        return 1

    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    features = _features([text], vectorizer, fit=False)

    label = int(model.predict(features)[0])
    proba = model.predict_proba(features)[0]
    confidence = proba[label] if label < len(proba) else max(proba)
    verdict = "PHISHING" if label == 1 else "legitimate"
    print(f"Prediction: {verdict}  (confidence {confidence:.0%})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    t = sub.add_parser("train", help="train and save the model")
    t.add_argument("--dataset", default="emails.csv", help="path to labelled CSV")

    p = sub.add_parser("predict", help="classify an email with the saved model")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", help="email text to classify")
    group.add_argument("--file", help="path to a file containing the email text")

    args = parser.parse_args(argv)

    if args.command == "train":
        return train(args.dataset)
    text = args.text if args.text is not None else Path(args.file).read_text(encoding="utf-8", errors="ignore")
    return predict(text)


if __name__ == "__main__":
    sys.exit(main())
