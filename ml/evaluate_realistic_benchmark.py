"""
PRAETOR benchmark evaluator.

Important:
- Dataset is split before fitting.
- No target-derived features.
- StandardScaler is fitted only on training data.
- Models are evaluated exclusively on held-out test data.
- Reports accuracy, macro precision, macro recall, macro F1,
  balanced accuracy and confusion matrices.
"""

from __future__ import annotations

from pathlib import Path
import json
import warnings

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    balanced_accuracy_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "ml" / "models" / "benchmark_dataset.csv"
OUT = ROOT / "ml" / "models" / "evaluation_results.json"
REPORT = ROOT / "ml" / "models" / "benchmark_report.json"

SEED = 20260825
TEST_SIZE = 0.25

warnings.filterwarnings("ignore")

df = pd.read_csv(DATA)

TARGET = "label"

X = df.drop(columns=[TARGET]).copy()
y = df[TARGET].copy()

# Explicit safety check against target-derived features.
for col in X.columns:
    lowered = col.lower()
    if lowered in {
        "label",
        "target",
        "class",
        "attack_type",
        "attack_label",
        "is_sql_injection",
        "is_xss",
        "is_port_scan",
        "is_brute_force",
        "is_command_injection",
        "is_malware",
        "is_path_traversal",
    }:
        raise RuntimeError(
            f"Potential target leakage detected in feature: {col}"
        )

# Remove duplicate feature rows before splitting.
before = len(X)
dedup = pd.concat([X, y], axis=1).drop_duplicates()
X = dedup.drop(columns=[TARGET])
y = dedup[TARGET]
duplicates_removed = before - len(X)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=TEST_SIZE,
    random_state=SEED,
    stratify=y,
)

classes = sorted(y.unique())
class_to_id = {c: i for i, c in enumerate(classes)}

y_train_id = y_train.map(class_to_id)
y_test_id = y_test.map(class_to_id)

# ------------------------------------------------------------
# Random Forest
# ------------------------------------------------------------

rf = RandomForestClassifier(
    n_estimators=350,
    max_depth=14,
    min_samples_leaf=3,
    max_features="sqrt",
    class_weight="balanced_subsample",
    random_state=SEED,
    n_jobs=-1,
)

rf.fit(X_train, y_train)
rf_pred = rf.predict(X_test)

# ------------------------------------------------------------
# XGBoost
# ------------------------------------------------------------

xgb = XGBClassifier(
    n_estimators=300,
    max_depth=5,
    learning_rate=0.045,
    subsample=0.82,
    colsample_bytree=0.78,
    min_child_weight=4,
    reg_lambda=2.0,
    objective="multi:softmax",
    num_class=len(classes),
    eval_metric="mlogloss",
    random_state=SEED,
    n_jobs=4,
)

xgb.fit(
    X_train,
    y_train_id,
)

xgb_pred_id = xgb.predict(X_test)
xgb_pred = pd.Series(xgb_pred_id).map(
    {v: k for k, v in class_to_id.items()}
).to_numpy()

def metrics(y_true, pred):
    return {
        "accuracy": round(float(accuracy_score(y_true, pred)), 4),
        "balanced_accuracy": round(
            float(balanced_accuracy_score(y_true, pred)), 4
        ),
        "precision_macro": round(
            float(
                precision_score(
                    y_true,
                    pred,
                    average="macro",
                    zero_division=0,
                )
            ),
            4,
        ),
        "recall_macro": round(
            float(
                recall_score(
                    y_true,
                    pred,
                    average="macro",
                    zero_division=0,
                )
            ),
            4,
        ),
        "f1_macro": round(
            float(
                f1_score(
                    y_true,
                    pred,
                    average="macro",
                    zero_division=0,
                )
            ),
            4,
        ),
        "confusion_matrix": confusion_matrix(
            y_true,
            pred,
            labels=classes,
        ).tolist(),
        "classification_report": classification_report(
            y_true,
            pred,
            labels=classes,
            output_dict=True,
            zero_division=0,
        ),
    }

results = {
    "random_forest": metrics(y_test, rf_pred),
    "xgboost": metrics(y_test, xgb_pred),
}

# ------------------------------------------------------------
# Isolation Forest
#
# Evaluate anomaly detection separately from multiclass
# classification. Treat only "benign" as normal.
# ------------------------------------------------------------

normal_train = X_train[y_train == "benign"]

scaler = StandardScaler()
normal_train_scaled = scaler.fit_transform(normal_train)
test_scaled = scaler.transform(X_test)

iso = IsolationForest(
    n_estimators=300,
    contamination=0.18,
    max_samples="auto",
    random_state=SEED,
    n_jobs=-1,
)

iso.fit(normal_train_scaled)

raw = iso.predict(test_scaled)

# Isolation Forest:
# +1 = normal
# -1 = anomaly
pred_anomaly = (raw == -1).astype(int)

# Everything except benign is treated as anomalous.
true_anomaly = (y_test != "benign").astype(int)

iso_accuracy = accuracy_score(true_anomaly, pred_anomaly)
iso_precision = precision_score(
    true_anomaly,
    pred_anomaly,
    zero_division=0,
)
iso_recall = recall_score(
    true_anomaly,
    pred_anomaly,
    zero_division=0,
)
iso_f1 = f1_score(
    true_anomaly,
    pred_anomaly,
    zero_division=0,
)

results["isolation_forest"] = {
    "accuracy": round(float(iso_accuracy), 4),
    "precision": round(float(iso_precision), 4),
    "recall": round(float(iso_recall), 4),
    "f1_score": round(float(iso_f1), 4),
    "normal_class": "benign",
    "anomaly_definition": "all non-benign traffic",
}

metadata = {
    "dataset": "benchmark_dataset.csv",
    "seed": SEED,
    "total_samples": int(len(df)),
    "duplicates_removed": int(duplicates_removed),
    "features": list(X.columns),
    "feature_count": int(len(X.columns)),
    "classes": classes,
    "test_size": TEST_SIZE,
    "train_samples": int(len(X_train)),
    "test_samples": int(len(X_test)),
    "evaluation_type": "held-out stratified test set",
    "target_leakage_check": "passed",
    "synthetic_data": True,
}

payload = {
    "benchmark_metadata": metadata,
    "models": results,
}

OUT.write_text(
    json.dumps(payload, indent=2),
    encoding="utf-8",
)

REPORT.write_text(
    json.dumps(payload, indent=2),
    encoding="utf-8",
)

print()
print("=" * 70)
print("PRAETOR REALISTIC BENCHMARK RESULTS")
print("=" * 70)

for name in ("random_forest", "xgboost"):
    r = results[name]
    print(
        f"{name:20s} "
        f"accuracy={r['accuracy']:.2%} "
        f"balanced={r['balanced_accuracy']:.2%} "
        f"macro-F1={r['f1_macro']:.2%}"
    )

r = results["isolation_forest"]
print(
    f"{'isolation_forest':20s} "
    f"accuracy={r['accuracy']:.2%} "
    f"precision={r['precision']:.2%} "
    f"recall={r['recall']:.2%} "
    f"F1={r['f1_score']:.2%}"
)

print("=" * 70)
print(f"Train samples: {len(X_train)}")
print(f"Test samples:  {len(X_test)}")
print(f"Duplicates removed: {duplicates_removed}")
print("Target leakage check: PASSED")
print(f"Results: {OUT}")
