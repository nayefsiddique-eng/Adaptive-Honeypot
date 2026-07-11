# PRAETOR — Research & Mathematical Specifications

---

## 1. Threat Model & Security Boundaries

PRAETOR operates under a structured threat model designed to capture remote adversarial interactions while defining defensive boundaries.

```
+-------------------------------------------------------------------------+
|                      Remote Attack Surface (Untrusted)                  |
|  [Port Sweeps]  -->  [Exploit Payloads]  -->  [Interactive Shell Drops] |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                       PRAETOR Security Boundary                         |
|   +--------------------------+          +---------------------------+   |
|   | iptables Redirect Layer  |  ----->  |  Decoy Container Sandbox  |   |
|   +--------------------------+          +---------------------------+   |
|                                                       |                 |
|                                                       v                 |
|   +--------------------------+          +---------------------------+   |
|   |  Host Operating System   |  <-----  | Ingestion API (Port 8000) |   |
|   | (Kernel, DB, RL Policies)|          |                           |   |
|   +--------------------------+          +---------------------------+   |
+-------------------------------------------------------------------------+
```

### Assumptions (Adversary Capabilities)
1. **Network Access:** The adversary has network visibility, allowing port scanning, metadata probing, and TCP/UDP communication.
2. **Standard Interfaces:** Attacker interaction is restricted to emulated ports and service decoy templates.

### Non-Capabilities (Security Bounding)
1. **Host Integrity:** The adversary cannot escape the docker decoy container sandbox or gain privilege escalation on the host OS.
2. **Database & Memory Isolation:** The adversary has no direct read/write access to the SQLite policy database (`honeypot.db`), local memory logs, or reinforcement learning parameter weights.
3. **Routing Bypass:** The adversary cannot bypass `netfilter`/`iptables` redirects.

---

## 2. Failure Modes & Limitations

PRAETOR is subject to the following structural limitations:
* **Zero-Interaction Probes:** Attackers executing fast, single-packet scans (e.g. `nmap -sS` without TCP handshakes) limit the duration parameters, reducing the reward feedback loop's gradient.
* **Encrypted Command Streams:** Payloads dropped over end-to-end encrypted tunnels (e.g., custom SSH configurations) prevent deep feature inspection, falling back to network-only metadata logs.
* **Supply-Chain & Physical Exploits:** Compromises targeting base dependencies or physical access bypass the software-defined redirect structures entirely.

---

## 3. Algorithm Complexity Analysis

| Module component | Algorithmic Process | Time Complexity | Space Complexity |
| :--- | :--- | :--- | :--- |
| **Behavior Graph** | Node Insertion & Path Edge Creation | $\mathcal{O}(V + E)$ | $\mathcal{O}(|V| + |E|)$ |
| **Campaign Similarity** | Cosine Vector Similarity Comparison | $\mathcal{O}(N \cdot |T|)$ | $\mathcal{O}(|T|)$ |
| **Decision Engine** | 9-Stage Ingestion Pipeline | $\mathcal{O}(1)$ | $\mathcal{O}(1)$ |
| **CMARL Policy** | Coordinated Action Search (Epsilon-Greedy) | $\mathcal{O}(|A|)$ | $\mathcal{O}(|S| \cdot |A|)$ |

---

## 4. Parameter Derivations & Reward Boundaries

### Multi-Agent Joint Reward Bounds
The joint reward function $R_{joint}(s)$ is bounded by:
$$R_{min} \le R_{joint}(s) \le R_{max}$$
* Under **optimal deception alignment** (attracting the attacker with matching profiles, deep session interaction, and maximum duration):
  $$R_{max} = 1.0 \cdot \min(15.0, 4.5) + 3.0 \cdot (3 \cdot 3.0) + 8.0 \cdot (0.9 \cdot 8.0) = 4.5 + 9.0 + 7.2 = 20.7$$
* Under **mismatched deception alignment** (attacker disconnects immediately):
  $$R_{min} = 1.0 \cdot \min(15.0, 0.1) + 3.0 \cdot (1 \cdot 3.0) + 8.0 \cdot (0.1 \cdot 8.0) = 0.1 + 3.0 + 0.8 = 3.9$$
These coefficients were calibrated using grid-search validation in pre-training runs to prevent service agent decisions from dominating network latency updates.
