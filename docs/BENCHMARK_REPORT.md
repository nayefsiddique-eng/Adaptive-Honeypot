# PRAETOR Scientific Benchmark & Evaluation Report

This report provides automated experimental validation metrics matching IEEE peer-review standards.

## 1. Deception Baseline Comparison
| Environment Profile | Mean Dwell Time (s) | Median Dwell Time (s) | Std Dev | 95% Confidence Interval |
| :--- | :---: | :---: | :---: | :---: |
| Static Honeypot | 17.58s | 18.04s | 4.12 | (16.11, 19.06) |
| Random Deception | 34.47s | 35.64s | 8.79 | (31.33, 37.62) |
| No Deception | 3.09s | 3.04s | 1.18 | (2.66, 3.51) |
| PRAETOR (CMARL) | 120.18s | 120.62s | 34.52 | (107.83, 132.54) |

## 2. Platform Ablation Metrics
| Configured Stack | Mean Threat Intelligence Points Captured | Degradation Ratio |
| :--- | :---: | :---: |
| Full Architecture | 67.6 | 0.0% |
| Without Behavior Graph | 42.95 | 36.46% |
| Without Threat Intelligence | 35.95 | 46.82% |
| Without CMARL Engine | 19.9 | 70.56% |

## 3. Stress & Scalability Performance
* **Simulated Sessions Processed:** `100`
* **Mean Decision Latency:** `2.4781 ms`
* **Max Decision Latency:** `4.0181 ms`
* **Throughput Performance:** `403.54 sessions/sec`
* **Total Execution Duration:** `0.2478 s`

## 4. Digital Twin Pre-training Transfer Effectiveness
* **Untrained Agent Mean Dwell Time:** `28.05s`
* **Pre-trained Agent Mean Dwell Time:** `132.21s`
* **Transfer Efficiency Factor:** `4.71x` (pre-trained vs untrained)
