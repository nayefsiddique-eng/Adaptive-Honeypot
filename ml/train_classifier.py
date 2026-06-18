import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

np.random.seed(42)
N = 5000

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

brute = make_samples("brute_force", N, {
    "is_ssh": np.ones(N), "port": np.full(N, 22),
    "protocol_ssh": np.ones(N),
    "has_common_password": np.random.choice([0,1], N, p=[0.2,0.8]),
    "login_attempts": np.random.randint(10, 100, N),
    "unique_usernames": np.random.randint(1, 20, N),
    "unique_passwords": np.random.randint(5, 50, N),
})

portscan = make_samples("port_scan", N, {
    "ports_scanned": np.random.randint(5, 50, N),
    "protocol_tcp": np.ones(N),
    "payload_length": np.random.randint(0, 20, N),
    "login_attempts": np.zeros(N),
})

sqli = make_samples("sql_injection", N, {
    "is_http": np.ones(N), "port": np.full(N, 80),
    "protocol_http": np.ones(N),
    "has_sql_injection": np.ones(N),
    "payload_length": np.random.randint(30, 200, N),
})

xss = make_samples("xss", N, {
    "is_http": np.ones(N), "port": np.full(N, 80),
    "protocol_http": np.ones(N),
    "has_xss": np.ones(N),
    "payload_length": np.random.randint(20, 150, N),
})

cmdinj = make_samples("command_injection", N, {
    "has_command_injection": np.ones(N),
    "protocol_http": np.ones(N),
    "payload_length": np.random.randint(10, 100, N),
})

malware = make_samples("malware_delivery", N, {
    "has_malware_extension": np.ones(N),
    "protocol_http": np.random.choice([0,1], N),
    "payload_length": np.random.randint(50, 500, N),
    "files_requested": np.random.randint(1, 10, N),
})

pathtr = make_samples("path_traversal", N, {
    "has_path_traversal": np.ones(N),
    "protocol_http": np.ones(N),
    "payload_length": np.random.randint(10, 80, N),
})

unknown = make_samples("unknown", N, {
    "payload_length": np.random.randint(0, 50, N),
})

df = pd.concat([brute, portscan, sqli, xss, cmdinj, malware, pathtr, unknown], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

FEATURES = [
    "port", "is_known_vuln_port", "is_ssh", "is_http", "is_ftp", "is_rdp",
    "payload_length", "has_common_password", "has_malware_extension",
    "has_sql_injection", "has_xss", "has_path_traversal", "has_command_injection",
    "protocol_tcp", "protocol_udp", "protocol_ssh", "protocol_http",
    "login_attempts", "unique_usernames", "unique_passwords",
    "commands_executed", "files_requested", "ports_scanned"
]

X = df[FEATURES]
y = df["label"]

le = LabelEncoder()
y_enc = le.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(X, y_enc, test_size=0.2, random_state=42)

print("Training Random Forest...")
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
rf_preds = rf.predict(X_test)
print("Random Forest Results:")
print(classification_report(y_test, rf_preds, target_names=le.classes_))

print("Training XGBoost...")
xgb = XGBClassifier(n_estimators=100, random_state=42, eval_metric="mlogloss", verbosity=0)
xgb.fit(X_train, y_train)
xgb_preds = xgb.predict(X_test)
print("XGBoost Results:")
print(classification_report(y_test, xgb_preds, target_names=le.classes_))

print("Training Isolation Forest (anomaly detection)...")
iso = IsolationForest(contamination=0.125, random_state=42)
iso.fit(X_train)

os.makedirs("ml/models", exist_ok=True)
joblib.dump(rf, "ml/models/random_forest.pkl")
joblib.dump(xgb, "ml/models/xgboost.pkl")
joblib.dump(iso, "ml/models/isolation_forest.pkl")
joblib.dump(le, "ml/models/label_encoder.pkl")
joblib.dump(FEATURES, "ml/models/feature_names.pkl")

print("All models saved to ml/models/")