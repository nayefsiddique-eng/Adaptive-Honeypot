# PRAETOR — Attacker Threat Model & Fingerprinting Risk Analysis

---

## 1. Assumed Attacker Capabilities

Adversaries interacting with PRAETOR are assumed to possess the following capabilities:
* **Network-Level Observability:** The attacker can run active scans, observe open ports, measure connection response latencies, and capture returned banners.
* **Multi-Session Tracking:** A persistent attacker can observe honeypot adaptations across multiple sessions from the same source IP or coordinate probes from diverse IPs.
* **Statistical Analysis:** The attacker can perform timing analysis and fingerprint specific profile updates over time.

---

## 2. Out-of-Scope Threats

The following attack vectors are explicitly out of scope for the current design:
* **Host & Sandbox Escape:** Attackers successfully escaping the decoy container to compromise the root host operating system.
* **Internal Database & Policy Access:** Direct write or read access to the SQLite policy database (`honeypot.db`), policy tables, or in-memory CMARL Q-tables.
* **Dependency & Supply-Chain Exploits:** Attacks targeting physical server hardware or injecting malicious code into third-party libraries.

---

## 3. Dynamic Fingerprinting & Epsilon Decay Limitations

A critical limitation in the current CMARL implementation is the **deterministic decay of epsilon** as a function of the overall session count:
$$\epsilon = \max\left(\epsilon_{\text{end}}, \epsilon_{\text{start}} - \frac{\text{Session Count}}{\text{Decay Steps}} \cdot (\epsilon_{\text{start}} - \epsilon_{\text{end}})\right)$$
Because exploration rates decrease deterministically, an advanced adversary querying the honeypot over a long sequence can statistically detect the transition from high-entropy (exploratory) actions to low-entropy (converged) actions. This predictability constitutes a fingerprinting signal that could allow an attacker to identify the environment as a honeypot. Acknowledging this design tradeoff is essential for deployment considerations.
