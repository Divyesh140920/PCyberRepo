import pandas as pd
import re
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import nltk
from nltk.corpus import stopwords
import joblib

nltk.download('stopwords')

# Example feature extraction functions
def count_urls(text):
    return len(re.findall(r'http[s]?://', text))

def count_keywords(text):
    phishing_keywords = ['urgent', 'password', 'verify', 'account', 'click', 'login', 'bank', 'update']
    return sum(text.lower().count(word) for word in phishing_keywords)

def preprocess_text(text):
    # Lowercase and remove non-alphabetic chars
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    # Remove stopwords
    stops = set(stopwords.words('english'))
    words = [word for word in text.lower().split() if word not in stops]
    return " ".join(words)

def load_dataset(path):
    # Expected CSV columns: 'email_text', 'label' (1=phishing, 0=legitimate)
    return pd.read_csv(path)

def feature_engineering(df):
    df['url_count'] = df['email_text'].apply(count_urls)
    df['keyword_count'] = df['email_text'].apply(count_keywords)
    df['clean_text'] = df['email_text'].apply(preprocess_text)
    return df

def train_model(df):
    vectorizer = TfidfVectorizer(max_features=3000)
    X_text = vectorizer.fit_transform(df['clean_text'])

    # Combine text features with engineered numeric features
    X = pd.concat([
        pd.DataFrame(X_text.toarray()),
        df[['url_count', 'keyword_count']].reset_index(drop=True)
    ], axis=1)

    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    # Save model and vectorizer for reuse
    joblib.dump(model, 'phishing_model.pkl')
    joblib.dump(vectorizer, 'tfidf_vectorizer.pkl')

def main():
    dataset_path = 'emails.csv'  # Replace with your dataset path
    df = load_dataset(dataset_path)
    df = feature_engineering(df)
    train_model(df)

if __name__ == "__main__":
    main()
