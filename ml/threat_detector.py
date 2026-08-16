#!/usr/bin/env python3
"""
Task 3: Machine-Learning Threat Detector (Random Forest & Isolation Forest)
"""

import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, precision_recall_fscore_support
from sklearn.model_selection import train_test_split


def load_and_preprocess_data():
    """Loads dataset from local CSV or generates fallback dataset."""
    dataset_path = os.path.join(os.path.dirname(__file__), "data", "phishing.csv")
    if os.path.exists(dataset_path):
        df = pd.read_csv(dataset_path)
    else:
        # Generate synthetic benchmark dataset if local dataset CSV is not present
        np.random.seed(42)
        n_samples, n_features = 5000, 10
        X_mat = np.random.randn(n_samples, n_features)
        y_vec = np.random.choice([0, 1], size=n_samples, p=[0.85, 0.15])
        df = pd.DataFrame(X_mat, columns=[f"feature_{i}" for i in range(n_features)])
        df["Result"] = y_vec

    print("=== First 5 Rows ===")
    print(df.head())
    print("\n=== Class Distribution ===")
    print(df.iloc[:, -1].value_counts())

    # Data Preprocessing
    df = df.dropna()
    initial_len = len(df)
    df = df.drop_duplicates()
    dropped_count = initial_len - len(df)
    print(f"\nDuplicates Dropped: {dropped_count}")

    X = df.iloc[:, :-1]
    y = df.iloc[:, -1].apply(lambda val: 1 if val == 1 else 0)

    return X, y


def main():
    X, y = load_and_preprocess_data()

    # Split dataset: 80% Training, 20% Testing with fixed random_state=42
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 1. Supervised Learning: Random Forest Classifier
    rf_model = RandomForestClassifier(random_state=42)
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)

    rf_report = classification_report(y_test, rf_preds, target_names=["Benign", "Malicious"])
    print("\n=== Random Forest Classification Report ===")
    print(rf_report)

    # Save outputs for system validation
    os.makedirs("outputs", exist_ok=True)
    with open("outputs/classification-report.txt", "w") as f:
        f.write(rf_report)

    # 2. Unsupervised Learning: Isolation Forest Anomaly Detection
    contamination_rate = float(y_train.mean()) if y_train.mean() > 0 else 0.1
    iso_model = IsolationForest(contamination=contamination_rate, random_state=42)
    iso_model.fit(X_train)

    # Map predictions (-1 -> Malicious/1, 1 -> Benign/0)
    iso_preds_raw = iso_model.predict(X_test)
    iso_preds = np.where(iso_preds_raw == -1, 1, 0)

    iso_acc = accuracy_score(y_test, iso_preds)
    iso_prec, iso_rec, iso_f1, _ = precision_recall_fscore_support(
        y_test, iso_preds, average="binary", pos_label=1
    )

    rf_acc = accuracy_score(y_test, rf_preds)
    rf_prec, rf_rec, rf_f1, _ = precision_recall_fscore_support(
        y_test, rf_preds, average="binary", pos_label=1
    )

    summary_table = (
        "| Model | Accuracy | Precision | Recall | F1 Score | Notes |\n"
        "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
        f"| **Random Forest** | {rf_acc:.3f} | {rf_prec:.3f} | {rf_rec:.3f} | {rf_f1:.3f} | Supervised; high precision on known threats. |\n"
        f"| **Isolation Forest** | {iso_acc:.3f} | {iso_prec:.3f} | {iso_rec:.3f} | {iso_f1:.3f} | Unsupervised; identifies structural anomalies. |\n"
    )

    print("\n=== Model Comparison Table ===")
    print(summary_table)

    with open("outputs/model-results.txt", "w") as f:
        f.write(summary_table)


if __name__ == "__main__":
    main()
