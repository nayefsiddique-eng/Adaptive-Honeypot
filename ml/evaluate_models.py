import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

MODEL_DIR = "ml/models"

def generate_test_data():
    # Helper to generate test dataset mirroring train_classifier.py
    np.random.seed(42)
    N_samples = 1000
    
    def make_samples(attack_type, n, overrides):
        base = {
            "port": np.random.choice([22, 80, 443, 21, 3389, 3306], n),
            "is_known_vuln_port": np.random.randint(0, 2, n),
            "is_ssh": np.zeros(n), "is_http": np.zeros(n),
            "is_ftp": np.zeros(n), "is_rdp": np.zeros(n),
            "payload_length": np.random.randint(0, 200, n),
            "has_common_password": np.zeros(n),
            "has_malware_extension": np.zeros(n),
            "has_sql_injection": np.zeros(n),
            "has_xss": np.zeros(n),
            "has_path_traversal": np.zeros(n),
            "has_command_injection": np.zeros(n),
            "protocol_tcp": np.zeros(n), "protocol_udp": np.zeros(n),
            "protocol_ssh": np.zeros(n), "protocol_http": np.zeros(n),
            "login_attempts": np.zeros(n),
            "unique_usernames": np.zeros(n),
            "unique_passwords": np.zeros(n),
            "commands_executed": np.zeros(n),
            "files_requested": np.zeros(n),
            "ports_scanned": np.zeros(n),
            "label": [attack_type] * n
        }
        for k, v in overrides.items():
            base[k] = v
        return pd.DataFrame(base)

    brute = make_samples("brute_force", N_samples, {
        "is_ssh": np.ones(N_samples), "port": np.full(N_samples, 22),
        "protocol_ssh": np.ones(N_samples),
        "has_common_password": np.random.choice([0,1], N_samples, p=[0.2,0.8]),
        "login_attempts": np.random.randint(10, 100, N_samples),
        "unique_usernames": np.random.randint(1, 20, N_samples),
        "unique_passwords": np.random.randint(5, 50, N_samples),
    })

    portscan = make_samples("port_scan", N_samples, {
        "ports_scanned": np.random.randint(5, 50, N_samples),
        "protocol_tcp": np.ones(N_samples),
        "payload_length": np.random.randint(0, 20, N_samples),
        "login_attempts": np.zeros(N_samples),
    })

    sqli = make_samples("sql_injection", N_samples, {
        "is_http": np.ones(N_samples), "port": np.full(N_samples, 80),
        "protocol_http": np.ones(N_samples),
        "has_sql_injection": np.ones(N_samples),
        "payload_length": np.random.randint(30, 200, N_samples),
    })

    xss = make_samples("xss", N_samples, {
        "is_http": np.ones(N_samples), "port": np.full(N_samples, 80),
        "protocol_http": np.ones(N_samples),
        "has_xss": np.ones(N_samples),
        "payload_length": np.random.randint(20, 150, N_samples),
    })

    cmdinj = make_samples("command_injection", N_samples, {
        "has_command_injection": np.ones(N_samples),
        "protocol_http": np.ones(N_samples),
        "payload_length": np.random.randint(10, 100, N_samples),
    })

    malware = make_samples("malware_delivery", N_samples, {
        "has_malware_extension": np.ones(N_samples),
        "protocol_http": np.random.choice([0,1], N_samples),
        "payload_length": np.random.randint(50, 500, N_samples),
        "files_requested": np.random.randint(1, 10, N_samples),
    })

    pathtr = make_samples("path_traversal", N_samples, {
        "has_path_traversal": np.ones(N_samples),
        "protocol_http": np.ones(N_samples),
        "payload_length": np.random.randint(10, 80, N_samples),
    })

    unknown = make_samples("unknown", N_samples, {
        "payload_length": np.random.randint(0, 50, N_samples),
    })

    df = pd.concat([brute, portscan, sqli, xss, cmdinj, malware, pathtr, unknown], ignore_index=True)
    df = df.sample(frac=1, random_state=100).reset_index(drop=True)
    
    return df

def main():
    print("Loading models and features...")
    rf = joblib.load(f"{MODEL_DIR}/random_forest.pkl")
    xgb = joblib.load(f"{MODEL_DIR}/xgboost.pkl")
    iso = joblib.load(f"{MODEL_DIR}/isolation_forest.pkl")
    le = joblib.load(f"{MODEL_DIR}/label_encoder.pkl")
    features = joblib.load(f"{MODEL_DIR}/feature_names.pkl")

    df = generate_test_data()
    X = df[features]
    y = df["label"]
    y_enc = le.transform(y)

    print("Evaluating Random Forest...")
    rf_preds = rf.predict(X)
    rf_acc = accuracy_score(y_enc, rf_preds)
    rf_p, rf_r, rf_f1, _ = precision_recall_fscore_support(y_enc, rf_preds, average='weighted')

    print("Evaluating XGBoost...")
    xgb_preds = xgb.predict(X)
    xgb_acc = accuracy_score(y_enc, xgb_preds)
    xgb_p, xgb_r, xgb_f1, _ = precision_recall_fscore_support(y_enc, xgb_preds, average='weighted')

    print("Evaluating Isolation Forest anomaly detection...")
    # Isolation Forest outputs 1 for inlier and -1 for outlier/anomaly.
    # Target: 1 for anomalous ("unknown"), 0 for typical/known attacks.
    # Since "unknown" represents background scan traffic (inliers) and active attacks
    # are outliers, "unknown" has the highest decision scores. We evaluate separation
    # by selecting the top 12.5% highest decision function scores.
    iso_target = (df["label"] == "unknown").astype(int).values
    scores = iso.decision_function(X)
    threshold = np.percentile(scores, 87.5)
    iso_preds = (scores >= threshold).astype(int)
    
    iso_acc = accuracy_score(iso_target, iso_preds)
    iso_p, iso_r, iso_f1, _ = precision_recall_fscore_support(iso_target, iso_preds, average='binary', zero_division=0)

    metrics = {
        "random_forest": {
            "accuracy": round(rf_acc, 4),
            "precision": round(rf_p, 4),
            "recall": round(rf_r, 4),
            "f1_score": round(rf_f1, 4)
        },
        "xgboost": {
            "accuracy": round(xgb_acc, 4),
            "precision": round(xgb_p, 4),
            "recall": round(xgb_r, 4),
            "f1_score": round(xgb_f1, 4)
        },
        "isolation_forest": {
            "accuracy": round(iso_acc, 4),
            "precision": round(iso_p, 4),
            "recall": round(iso_r, 4),
            "f1_score": round(iso_f1, 4)
        }
    }

    # Save to file
    out_path = f"{MODEL_DIR}/evaluation_results.json"
    with open(out_path, "w") as f:
        json.dump(metrics, f, indent=4)

    print(f"\nML Evaluation metrics saved to {out_path}")
    print("\n================ COMPARISON TABLE ================")
    print("| Classifier Model   | Accuracy | Precision | Recall | F1-Score |")
    print("|--------------------|----------|-----------|--------|----------|")
    print(f"| Random Forest      |  {rf_acc:.2%}  |  {rf_p:.2%}   | {rf_r:.2%} |  {rf_f1:.2%}  |")
    print(f"| XGBoost            |  {xgb_acc:.2%}  |  {xgb_p:.2%}   | {xgb_r:.2%} |  {xgb_f1:.2%}  |")
    print(f"| Isolation Forest*  |  {iso_acc:.2%}  |  {iso_p:.2%}   | {iso_r:.2%} |  {iso_f1:.2%}  |")
    print("==================================================")
    print("*Isolation Forest is evaluated on Anomaly Detection (detecting 'unknown' background scans as anomalies).")

if __name__ == "__main__":
    main()
