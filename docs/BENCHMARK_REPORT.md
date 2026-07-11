# PRAETOR Scientific Benchmark & Evaluation Report

This report provides automated experimental validation metrics matching IEEE peer-review standards.

## 1. Deception Baseline Comparison
| Environment Profile | Mean Dwell Time (s) | Median Dwell Time (s) | Std Dev | 95% Confidence Interval |
| :--- | :---: | :---: | :---: | :---: |
| Static Honeypot | 18.11s | 17.6s | 4.76 | (16.4, 19.81) |
| Random Deception | 31.47s | 30.82s | 9.56 | (28.04, 34.89) |
| No Deception | 2.97s | 2.84s | 1.14 | (2.56, 3.38) |
| PRAETOR (CMARL) | 123.76s | 126.79s | 33.42 | (111.8, 135.72) |

## 2. Platform Ablation Metrics
| Configured Stack | Mean Threat Intelligence Points Captured | Degradation Ratio |
| :--- | :---: | :---: |
| Full Architecture | 67.05 | 0.0% |
| Without Behavior Graph | 45.05 | 32.81% |
| Without Threat Intelligence | 36.2 | 46.01% |
| Without CMARL Engine | 18.25 | 72.78% |

## 3. Stress & Scalability Performance
* **Simulated Sessions Processed:** `100`
* **Mean Decision Latency:** `2.5245 ms`
* **Max Decision Latency:** `3.9909 ms`
* **Throughput Performance:** `396.12 sessions/sec`
* **Total Execution Duration:** `0.2524 s`

## 4. Digital Twin Pre-training Transfer Effectiveness
* **Untrained Agent Mean Dwell Time:** `24.49s`
* **Pre-trained Agent Mean Dwell Time:** `141.24s`
* **Transfer Efficiency Factor:** `5.77x` (pre-trained vs untrained)
