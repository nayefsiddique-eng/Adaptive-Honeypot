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
    if os.environ.get("DISABLE_ML_MODELS") == "1":
        print("ML model loading disabled via environment — running in heuristic-only mode")
        return
    try:
        _rf = joblib.load(f"{MODEL_DIR}/random_forest.pkl")
        _xgb = joblib.load(f"{MODEL_DIR}/xgboost.pkl")
        _iso = joblib.load(f"{MODEL_DIR}/isolation_forest.pkl")
        _le = joblib.load(f"{MODEL_DIR}/label_encoder.pkl")
        _features = joblib.load(f"{MODEL_DIR}/feature_names.pkl")
        print("ML models loaded successfully")
    except FileNotFoundError:
        print("ML model files not found — running in heuristic-only mode")
    except Exception as e:
        print(f"ML model loading failed: {e} — running in heuristic-only mode")

def models_loaded():
    return _rf is not None

def predict(features: dict) -> dict:
    if not models_loaded():
        return {"attack_type": "unknown", "confidence": 0.0, "is_anomaly": False, "model": "none"}

    import pandas as pd
    X = pd.DataFrame([[features.get(f, 0) for f in _features]], columns=_features)

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

    # If ML ensemble yields 'unknown' or misclassifies live protocol traffic as generic port_scan, fallback to heuristic classification
    from backend.core.feature_extractor import classify_attack_heuristic
    heuristic_label = classify_attack_heuristic(features)
    if heuristic_label != "unknown":
        if final_label in ["unknown", "port_scan"] or final_confidence < 0.35:
            if final_label == "port_scan" and (features.get("is_ssh_login") or features.get("is_shell_command") or features.get("has_common_password") or features.get("protocol_http") or features.get("protocol_telnet") or features.get("protocol_ssh")):
                final_label = heuristic_label
                winning_model = f"{winning_model}+heuristic"
            elif final_label == "unknown" or final_confidence < 0.35:
                final_label = heuristic_label
                winning_model = f"{winning_model}+heuristic"

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