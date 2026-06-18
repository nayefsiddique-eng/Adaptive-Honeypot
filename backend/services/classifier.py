import joblib
import numpy as np
import os

MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "ml", "models"))

_rf = None
_xgb = None
_iso = None
_le = None
_features = None

def load_models():
    global _rf, _xgb, _iso, _le, _features
    _rf = joblib.load(f"{MODEL_DIR}/random_forest.pkl")
    _xgb = joblib.load(f"{MODEL_DIR}/xgboost.pkl")
    _iso = joblib.load(f"{MODEL_DIR}/isolation_forest.pkl")
    _le = joblib.load(f"{MODEL_DIR}/label_encoder.pkl")
    _features = joblib.load(f"{MODEL_DIR}/feature_names.pkl")
    print("ML models loaded successfully")

def models_loaded():
    return _rf is not None

def predict(features: dict) -> dict:
    if not models_loaded():
        return {"attack_type": "unknown", "confidence": 0.0, "is_anomaly": False, "model": "none"}

    X = np.array([[features.get(f, 0) for f in _features]])

    rf_pred = _rf.predict(X)[0]
    rf_proba = _rf.predict_proba(X)[0]
    rf_confidence = float(np.max(rf_proba))
    rf_label = _le.inverse_transform([rf_pred])[0]

    xgb_pred = _xgb.predict(X)[0]
    xgb_proba = _xgb.predict_proba(X)[0]
    xgb_confidence = float(np.max(xgb_proba))
    xgb_label = _le.inverse_transform([xgb_pred])[0]

    iso_score = _iso.decision_function(X)[0]
    is_anomaly = bool(_iso.predict(X)[0] == -1)

    if rf_confidence >= xgb_confidence:
        final_label = rf_label
        final_confidence = rf_confidence
        winning_model = "random_forest"
    else:
        final_label = xgb_label
        final_confidence = xgb_confidence
        winning_model = "xgboost"

    return {
        "attack_type": final_label,
        "confidence": round(final_confidence, 4),
        "is_anomaly": is_anomaly,
        "anomaly_score": round(float(iso_score), 4),
        "model": winning_model,
        "rf_label": rf_label,
        "rf_confidence": round(rf_confidence, 4),
        "xgb_label": xgb_label,
        "xgb_confidence": round(xgb_confidence, 4),
    }