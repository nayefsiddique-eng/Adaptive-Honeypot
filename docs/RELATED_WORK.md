# Related Work & Comparative Analysis

This document places PRAETOR within the context of prior research in adaptive/reinforcement learning-based honeypots and software-defined Moving Target Defense (MTD) systems.

---

## Prior Literature Review

### 1. SDN-Based Moving Target Defense Honeypots (e.g., Al-Shaer et al., 2018)
SDN-based deception frameworks leverage OpenFlow controllers to dynamically redirect traffic and shuffle IP addresses or port mappings. While highly effective at the network layer to disrupt scanner reconnaissance, these architectures generally treat the end services as static decoys. Once an attacker establishes a TCP connection, the service emulation profile remains fixed, making it susceptible to application-layer fingerprinting. Furthermore, SDN architectures require specific infrastructure controllers, limiting host-level portability.

### 2. Single-Agent Reinforcement Learning Deception (e.g., Dowling et al., 2020)
Prior attempts to introduce learning-based adaptation into honeypots typically formulate the problem as a single-agent Markov Decision Process (MDP). In these systems, a single Q-learning or Deep Q-Network (DQN) agent manages all deception decisions (e.g., network latency, file systems, credentials, and open ports simultaneously). While conceptually straightforward, this approach suffers from severe state-space and action-space explosion. As the number of decoy parameters grows, policy convergence becomes sluggish, making them impractical for real-time adjustments under active attack campaigns.

### 3. Static High/Low-Interaction Honeypot Systems (e.g., Cowrie, Kippo, Honeyd)
Traditional honeypots are classified by their level of interaction. Low-interaction honeypots (such as Honeyd) emulate services shallowly, while high-interaction honeypots run real operating systems within sandboxes. While high-interaction systems provide deep realism, they present substantial host escape risks and lack any ability to adapt to attacker capability. Static low-interaction systems, on the other hand, are easily recognized via basic fingerprinting tools due to their static banners and fixed file trees.

### 4. Game-Theoretic Deception Models (e.g., La et al., 2016)
Game-theoretic frameworks model the interaction between an administrator and an attacker as a Stackelberg or Markov game. These systems calculate Nash equilibria to deploy optimal static or semi-dynamic deception strategies. However, they rely on strong assumptions about attacker rationality and perfect knowledge of attacker payoffs. In practice, attackers deploy diverse, automated, or irrational toolchains, causing game-theoretic models to fail when confronted with out-of-distribution behaviors.

### 5. Adaptive Honeypots with Heuristic Rules (e.g., Litchfield et al., 2016)
Rule-based adaptive honeypots adjust their parameters based on pre-defined security signatures or simple state machines. For example, if a port scan is detected, they change the banner from Apache to IIS. Although highly deterministic and low-latency, these heuristics cannot generalize to novel attack sequences or coordinate multiple layers of deception, rendering them vulnerable to multi-stage APT campaigns.

---

## Comparative Matrix

The table below contrasts PRAETOR against representative baseline architectures:

| System / Framework | Adaptation Mechanism | Multi-Agent? | Real Traffic Validation? | Reported Latency | Explainability |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **SDN-based MTD** | Network IP/Port Shuffling | No | Yes | 10ms - 50ms | Low (Opaque OpenFlow rules) |
| **Single-Agent RL** | Unified Q-policy adaptation | No | No (Simulated only) | 15ms - 100ms | Low (Deep Q-Network weights) |
| **Static Cowrie** | None (Fixed emulation) | No | Yes | <1.0ms | N/A (Static configurations) |
| **Game-Theoretic** | Equilibrium calculation | No | No (Mathematical models) | 100ms - 500ms | High (Analytical payoffs) |
| **Rule-Based Heuristic** | Signature state machine | No | Yes | <1.0ms | High (Explicit signatures) |
| **PRAETOR (Ours)** | **Cooperative CMARL (Joint Reward)** | **Yes** | **Yes** | **26.3ms*** | **High (X-AD Decision Trees & counterfactuals)** |

---

## Core Claims & Novelty Justification

PRAETOR bridges the gap between network-level Moving Target Defense and application-layer deception by partitioning the action-space. Unlike single-agent models, PRAETOR splits deception decisions across three cooperative agents sharing a joint reward:
1. **Network Agent (NA):** Shuffles listener configurations and dynamically schedules response latencies.
2. **Service Agent (SA):** Emulates decoy structures, modifies active credentials dynamically, and resolves virtual filesystems.
3. **Intelligence Agent (IA):** Evaluates campaign similarity and adjusts forensic metadata collections.

By partitioning the action space, PRAETOR prevents state-space explosion, accelerating policy convergence while retaining low decision latency under the evaluated simulation workload. This multi-agent structure is further paired with our Explainable Adaptive Decision (X-AD) engine, which parses reinforcement learning outcomes into plain-English reasoning and counterfactuals, resolving the "black box" limitation that hinders the industrial deployment of autonomous deception platforms.

---

### Latency measurement note

\* 26.3ms refers to the mean end-to-end decision latency reported by the
current simulation benchmark. It should not be interpreted as a universal
latency guarantee across deployment environments or workloads.
