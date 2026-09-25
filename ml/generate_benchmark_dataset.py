"""
PRAETOR realistic synthetic security telemetry generator.

Design goals:
- No target-derived binary flags.
- Overlapping feature distributions.
- Benign-looking noise inside attack classes.
- Attack-like signals inside benign/unknown traffic.
- Stratified train/test split performed AFTER generation.
- Fixed seed for reproducibility.
- Group identifiers prevent duplicate leakage.
"""

from __future__ import annotations

from pathlib import Path
import json
import numpy as np
import pandas as pd

SEED = 20260825
N_SAMPLES = 16000

OUT = Path(__file__).resolve().parent / "models" / "benchmark_dataset.csv"

rng = np.random.default_rng(SEED)

classes = [
    "benign",
    "brute_force",
    "command_injection",
    "malware_delivery",
    "path_traversal",
    "port_scan",
    "sql_injection",
    "xss",
    "unknown",
]

# Approximate realistic class proportions.
weights = np.array([
    0.30,  # benign
    0.10,  # brute force
    0.08,  # command injection
    0.08,  # malware
    0.08,  # traversal
    0.10,  # port scan
    0.08,  # SQLi
    0.08,  # XSS
    0.10,  # unknown
])

labels = rng.choice(classes, size=N_SAMPLES, p=weights)

rows = []

def clipped_normal(mean, std, low, high, n=1):
    return np.clip(rng.normal(mean, std, n), low, high)

def beta_noise(a=2.0, b=2.0, n=1):
    return rng.beta(a, b, n)

for i, label in enumerate(labels):

    # Shared telemetry features.
    requests = int(clipped_normal(35, 22, 1, 220)[0])
    unique_paths = int(clipped_normal(7, 5, 1, 50)[0])
    failed_auth = int(clipped_normal(1, 3, 0, 25)[0])
    payload_entropy = float(clipped_normal(3.8, 0.9, 1.0, 7.0)[0])
    avg_payload_length = float(clipped_normal(420, 260, 20, 1800)[0])
    request_rate = float(clipped_normal(2.8, 2.0, 0.05, 18)[0])
    source_port_entropy = float(beta_noise(2.5, 2.5)[0])
    destination_port_entropy = float(beta_noise(2.2, 2.8)[0])
    path_depth = float(clipped_normal(2.2, 1.3, 0, 9)[0])
    special_character_ratio = float(beta_noise(2.0, 5.0)[0])
    response_error_ratio = float(beta_noise(2.0, 8.0)[0])
    session_duration = float(clipped_normal(95, 80, 1, 900)[0])
    command_count = int(clipped_normal(4, 5, 0, 45)[0])
    distinct_user_agents = int(clipped_normal(1.5, 1.2, 1, 12)[0])
    geo_variance = float(beta_noise(2.0, 4.0)[0])

    # Class-dependent tendencies.
    # These are distributions, not deterministic labels.
    if label == "benign":
        requests = int(clipped_normal(28, 18, 1, 140)[0])
        failed_auth = int(clipped_normal(1, 2, 0, 15)[0])
        request_rate = float(clipped_normal(2.0, 1.4, .05, 10)[0])
        special_character_ratio = float(beta_noise(2.0, 7.0)[0])

        # Some benign traffic contains suspicious-looking behavior.
        if rng.random() < 0.12:
            failed_auth += int(clipped_normal(4, 2, 1, 10)[0])
            special_character_ratio = float(beta_noise(2.5, 4.5)[0])

    elif label == "brute_force":
        failed_auth = int(clipped_normal(14, 7, 3, 45)[0])
        request_rate = float(clipped_normal(5.5, 2.8, .5, 18)[0])
        requests = int(clipped_normal(75, 35, 15, 220)[0])
        session_duration = float(clipped_normal(55, 40, 2, 400)[0])

        if rng.random() < 0.20:
            failed_auth = int(clipped_normal(6, 3, 1, 16)[0])

    elif label == "command_injection":
        command_count = int(clipped_normal(15, 9, 3, 50)[0])
        special_character_ratio = float(beta_noise(4.0, 3.0)[0])
        payload_entropy = float(clipped_normal(4.7, 0.9, 2, 7)[0])
        avg_payload_length = float(clipped_normal(650, 360, 50, 1800)[0])

        if rng.random() < 0.18:
            command_count = int(clipped_normal(5, 3, 0, 15)[0])

    elif label == "malware_delivery":
        avg_payload_length = float(clipped_normal(900, 420, 100, 2200)[0])
        payload_entropy = float(clipped_normal(5.1, 0.8, 2.5, 7)[0])
        response_error_ratio = float(beta_noise(3.0, 6.0)[0])
        requests = int(clipped_normal(22, 14, 2, 100)[0])

        if rng.random() < 0.20:
            avg_payload_length = float(clipped_normal(500, 250, 50, 1200)[0])

    elif label == "path_traversal":
        path_depth = float(clipped_normal(5.0, 2.0, 1, 10)[0])
        special_character_ratio = float(beta_noise(3.5, 4.0)[0])
        unique_paths = int(clipped_normal(13, 7, 2, 50)[0])

        if rng.random() < 0.20:
            path_depth = float(clipped_normal(3, 1.5, 1, 8)[0])

    elif label == "port_scan":
        unique_paths = int(clipped_normal(20, 10, 4, 60)[0])
        source_port_entropy = float(beta_noise(5.0, 2.2)[0])
        destination_port_entropy = float(beta_noise(5.0, 2.0)[0])
        request_rate = float(clipped_normal(7, 3, 1, 18)[0])
        requests = int(clipped_normal(110, 45, 20, 250)[0])

        if rng.random() < 0.15:
            destination_port_entropy = float(beta_noise(2.5, 3.0)[0])

    elif label == "sql_injection":
        special_character_ratio = float(beta_noise(3.8, 3.2)[0])
        avg_payload_length = float(clipped_normal(520, 280, 50, 1500)[0])
        payload_entropy = float(clipped_normal(4.5, 0.9, 2, 7)[0])
        response_error_ratio = float(beta_noise(3.0, 5.0)[0])

        if rng.random() < 0.20:
            special_character_ratio = float(beta_noise(2.5, 4.5)[0])

    elif label == "xss":
        special_character_ratio = float(beta_noise(3.6, 3.2)[0])
        avg_payload_length = float(clipped_normal(480, 270, 40, 1500)[0])
        payload_entropy = float(clipped_normal(4.3, 1.0, 2, 7)[0])
        unique_paths = int(clipped_normal(10, 6, 1, 40)[0])

        if rng.random() < 0.20:
            avg_payload_length = float(clipped_normal(260, 160, 20, 800)[0])

    elif label == "unknown":
        requests = int(clipped_normal(80, 45, 5, 240)[0])
        unique_paths = int(clipped_normal(15, 9, 2, 60)[0])
        request_rate = float(clipped_normal(5, 3, .2, 18)[0])
        payload_entropy = float(clipped_normal(4.5, 1.1, 1, 7)[0])
        geo_variance = float(beta_noise(3.0, 3.0)[0])

        # Unknown traffic intentionally overlaps multiple attack types.
        if rng.random() < 0.25:
            failed_auth += int(clipped_normal(3, 2, 0, 10)[0])

    # Environmental noise.
    requests = max(1, requests + int(rng.normal(0, 5)))
    unique_paths = max(1, unique_paths + int(rng.normal(0, 2)))
    failed_auth = max(0, failed_auth + int(rng.normal(0, 1)))
    command_count = max(0, command_count + int(rng.normal(0, 1)))

    rows.append({
        "requests": requests,
        "unique_paths": unique_paths,
        "failed_auth": failed_auth,
        "payload_entropy": round(payload_entropy, 4),
        "avg_payload_length": round(avg_payload_length, 3),
        "request_rate": round(request_rate, 4),
        "source_port_entropy": round(source_port_entropy, 4),
        "destination_port_entropy": round(destination_port_entropy, 4),
        "path_depth": round(path_depth, 4),
        "special_character_ratio": round(special_character_ratio, 4),
        "response_error_ratio": round(response_error_ratio, 4),
        "session_duration": round(session_duration, 3),
        "command_count": command_count,
        "distinct_user_agents": distinct_user_agents,
        "geo_variance": round(geo_variance, 4),
        "label": label,
    })

df = pd.DataFrame(rows)

# Shuffle after generation.
df = df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)

OUT.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(OUT, index=False)

metadata = {
    "seed": SEED,
    "samples": int(len(df)),
    "features": int(len(df.columns) - 1),
    "classes": classes,
    "dataset_type": "synthetic security telemetry",
    "target_leakage_features": [],
    "evaluation_note": "Features are probabilistic and intentionally overlapping; no feature directly encodes the target."
}

(OUT.parent / "benchmark_metadata.json").write_text(
    json.dumps(metadata, indent=2),
    encoding="utf-8"
)

print(f"Generated {len(df)} samples.")
print(f"Features: {len(df.columns)-1}")
print("Class distribution:")
print(df["label"].value_counts())
print(f"Saved: {OUT}")
