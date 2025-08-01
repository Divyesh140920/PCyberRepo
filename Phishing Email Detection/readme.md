# Phishing Email Detection using Machine Learning

## Description
This project builds a machine learning model in Python to classify emails as phishing or legitimate based on their content. It demonstrates:

- Data preprocessing and cleaning
- Feature engineering (URL counts, phishing-related keywords)
- Text vectorization using TF-IDF
- Training and evaluating a Random Forest classifier

## Features
- Extracts features from email text such as number of URLs and phishing keywords.
- Cleans email text and removes stopwords.
- Trains a Random Forest model on a labeled email dataset.
- Provides classification accuracy and detailed metrics.
- Saves the trained model and vectorizer for future use.

## Requirements
- Python 3.x
- `pandas`, `scikit-learn`, `nltk`, `joblib`

Install dependencies with:

`pip install pandas scikit-learn nltk joblib`


## Usage
1. Prepare a labeled dataset CSV file (`emails.csv`) with columns:
   - `email_text`: raw email content
   - `label`: 1 for phishing, 0 for legitimate
2. Run the script:`python phishing_email_detector.py`
3. The model will train and output evaluation metrics.

## Dataset
You can use publicly available phishing email datasets, or create your own labeled data.

## Disclaimer
This is a basic implementation for educational purposes and may require further improvements for production use.
