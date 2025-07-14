import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

# Load dataset
data = pd.read_csv('custom_phishing_dataset.csv')

# Features and labels
X = data[['Have_IP', 'Have_At_Symbol', 'URL_Length', 'Is_Https']]
y = data['Is_Phishing']

# Train model
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=1)
model = LogisticRegression()
model.fit(X_train, y_train)

print("\nModel trained successfully.")
print(f"Accuracy on test set: {accuracy_score(y_test, model.predict(X_test)):.2f}\n")

# Predict using DataFrame (fixes the sklearn warning)
def predict_with_feature_names(model, feature_list):
    columns = ['Have_IP', 'Have_At_Symbol', 'URL_Length', 'Is_Https']
    df = pd.DataFrame([feature_list], columns=columns)
    return model.predict(df)[0]

# Feature extraction from URL
def extract_features_from_url(url):
    parsed = urlparse(url)
    have_ip = 1 if re.match(r'^http[s]?://(\d{1,3}\.){3}\d{1,3}', url) else 0
    at_symbol = 1 if '@' in url else 0
    url_length = len(url)
    https = 1 if parsed.scheme == "https" else 0
    return [have_ip, at_symbol, url_length, https]

# CLI
def run_cli():
    while True:
        print("Phishing URL Detection")
        print("1. Predict from manual feature input")
        print("2. Predict from actual URL")
        print("3. Exit")
        choice = input("Select an option (1/2/3): ")

        if choice == '1':
            try:
                ip = int(input("Contains IP? (1 = Yes, 0 = No): "))
                at = int(input("Contains @ symbol? (1 = Yes, 0 = No): "))
                length = int(input("Enter URL length (number): "))
                https = int(input("Uses HTTPS? (1 = Yes, 0 = No): "))
                features = [ip, at, length, https]
                result = predict_with_feature_names(model, features)
                print("Prediction:", "Phishing" if result == 1 else "Legitimate")
            except:
                print("Invalid input. Please enter numeric values only.")

        elif choice == '2':
            url = input("Enter full URL (e.g., http://example.com): ")
            features = extract_features_from_url(url)
            result = predict_with_feature_names(model, features)
            print(f"Extracted Features: {features}")
            print("Prediction:", "Phishing" if result == 1 else "Legitimate")

        elif choice == '3':
            print("Exiting program.")
            break
        else:
            print("Invalid option. Please choose 1, 2, or 3.")

        print("-" * 50)

# Run the CLI
if __name__ == "__main__":
    run_cli()
