# PRAETOR — Artifact Evaluation & Replication Guide

---

## 1. Hyperparameter Configurations

The table below documents the hyperparameter values used in the CMARL (Cooperative Multi-Agent Reinforcement Learning) engine:

| Parameter | Symbol | Value | Optimization / Selection Method |
| :--- | :---: | :---: | :--- |
| **Learning Rate** | $\alpha$ | `0.10` | Calibrated via grid-search to prevent policy oscillation. |
| **Discount Factor** | $\gamma$ | `0.90` | Selected to balance immediate and long-term reward values. |
| **Initial Exploration** | $\epsilon_{\text{start}}$ | `0.30` | Configured to ensure sufficient initial exploration. |
| **End Exploration** | $\epsilon_{\text{end}}$ | `0.05` | Sets the minimum exploration floor. |
| **Decay Steps** | - | `150` | Automatically decays exploration over 150 sessions. |
| **Deception Weight** | $\omega_1$ | `8.0` | Joint reward coefficient for profile alignment. |
| **Interaction Depth Weight** | $\omega_2$ | `3.0` | Joint reward coefficient for attack depth. |
| **Duration Weight** | $\omega_3$ | `1.0` | Joint reward coefficient for connection duration. |

---

## 2. Experimental Protocols

To replicate the evaluations presented in the benchmark report, follow these protocols:

### Protocol A: Attacker Persona Simulation (Baseline Validation)
1. **Goal:** Verify the mean and median attacker dwell times across different deception setups.
2. **Execution:**
   * Run the benchmark script: `python scripts/run_benchmarks.py`
   * The script instantiates the `DeceptionDigitalTwin` with a seed, runs 30 simulated sessions per baseline, and calculates the 95% Confidence Intervals.

### Protocol B: Ablation Study Verification
1. **Goal:** Measure performance degradation when disabling specific architectural components.
2. **Execution:**
   * The framework sequentially isolates the Behavior Graph, Threat Intelligence, and CMARL modules.
   * Compare the resulting mean intelligence points against the baseline execution.

---

## 3. Ethics & Containment Statement

PRAETOR is designed as a defensive security research platform. To ensure ethical and safe operations, the platform adheres to these containment guidelines:
* **Decoy Isolation:** All decoy targets run inside isolated environments (Docker containers) with restricted local network access to prevent lateral movement.
* **Controlled Redirection:** Port mutations and software-defined redirects (`iptables`) target only incoming traffic destined for designated honeypot IPs.
* **No Offensive Capabilities:** The platform contains no active exploit tools or payload propagation mechanisms.

---

## 4. Reproducibility & Replication Checklist

### Hardware Requirements
* **CPU:** Intel Core i5/AMD Ryzen 5 or higher (dual-core minimum).
* **Memory:** 8 GB RAM (16 GB recommended to support concurrent docker container tests).
* **Storage:** 2 GB free disk space.

### Environment & Software
* **Operating System:** Windows 10/11 (with WSL2) or Ubuntu 20.04/22.04 LTS.
* **Python Version:** `Python 3.12`
* **Docker Engine:** `Version 20.10` or higher (for container emulation).

### Step-by-Step Verification Command List
```bash
# 1. Activate the virtual environment
source venv/bin/activate  # Or .\venv\Scripts\activate on Windows

# 2. Run the test suite to verify module integrity
python -m pytest tests/

# 3. Execute the automated benchmark suite
python scripts/run_benchmarks.py

# 4. Inspect the generated report
cat docs/BENCHMARK_REPORT.md
```
