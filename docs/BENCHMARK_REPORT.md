# PRAETOR Benchmark Report

## Evaluation Methodology

PRAETOR is evaluated using a reproducible synthetic security-telemetry
dataset generated specifically for this repository.

The benchmark intentionally uses overlapping probabilistic feature
distributions rather than deterministic attack flags. Some benign
traffic contains attack-like characteristics, while some attack traffic
does not contain every obvious indicator.

The target label is not directly encoded as a feature.

### Dataset

- Total samples: 16000
- Features: 15
- Classes: 9
- Train samples: 12000
- Test samples: 4000
- Test split: 25%
- Random seed: 20260825
- Duplicates removed before split: 0
- Evaluation: stratified held-out test set
- Target leakage check: passed

### Multiclass Classification

| Model | Accuracy | Balanced Accuracy | Macro Precision | Macro Recall | Macro F1 |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Random Forest | 69.40% | 65.90% | 66.52% | 65.90% | 66.02% |
| XGBoost | 71.90% | 66.14% | 69.10% | 66.14% | 67.31% |

### Anomaly Detection

Isolation Forest is evaluated separately as a binary anomaly detector.

Normal traffic is defined as `benign`; all other classes are treated as
anomalous.

| Model | Accuracy | Precision | Recall | F1 |
| :--- | ---: | ---: | ---: | ---: |
| Isolation Forest | 77.08% | 90.09% | 75.60% | 82.21% |

## Interpretation

These results are generated from synthetic security telemetry and a
held-out test set. They demonstrate the behavior of the implemented
classification and anomaly-detection pipeline.

They are not claims of real-world Internet attack detection accuracy.
Validation against live attacker traffic, enterprise telemetry, and
independently collected datasets remains future work.

The benchmark is intended to be reproducible and transparent rather
than to maximize reported accuracy.
