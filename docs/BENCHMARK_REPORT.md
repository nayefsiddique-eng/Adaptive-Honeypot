# PRAETOR Scientific Benchmark & Evaluation Report

Benchmark results covering deception performance, ablation impact, stress/scalability, and pre-training transfer effectiveness for the PRAETOR adaptive honeypot system.

---

## 1. Deception Baseline Comparison

| Environment Profile | Mean Dwell Time (s) | Median Dwell Time (s) | Std Dev | 95% CI |
| :--- | :---: | :---: | :---: | :---: |
| Static Honeypot | 17.12 | 17.35 | 4.33 | (15.56, 18.67) |
| Random Deception | 27.61 | 25.50 | 10.15 | (23.98, 31.24) |
| No Deception | 2.70 | 2.49 | 1.37 | (2.21, 3.19) |
| PRAETOR (CMARL) | 122.83 | 124.36 | 31.84 | (111.43, 134.22) |

---

## 2. Platform Ablation Metrics

| Configured Stack | Mean Threat Intel Points Captured | Degradation Ratio |
| :--- | :---: | :---: |
| Full Architecture | 68.35 | 0.0% |
| Without Behavior Graph | 47.25 | 30.87% |
| Without Threat Intelligence | 38.65 | 43.45% |
| Without CMARL Engine | 20.80 | 69.57% |

---

## 3. Stress & Scalability Performance

| Metric | Simulated | Live (Trained System) |
| :--- | :---: | :---: |
| Sessions Processed | 100 | 100 |
| Mean Decision Latency | 6.8989 ms | 3.7388 ms |
| Max Decision Latency | 40.4837 ms | 13.9945 ms |
| Throughput | 144.92 sessions/sec | 267.39 sessions/sec |
| Total Execution Duration | 0.6900 s | 0.3740 s |

---

## 4. Digital Twin Pre-training Transfer Effectiveness

* **Untrained Agent Mean Dwell Time:** 25.33s
* **Pre-trained Agent Mean Dwell Time:** 157.1s
* **Transfer Efficiency Factor:** 6.2x (pre-trained vs. untrained)