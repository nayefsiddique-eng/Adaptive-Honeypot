# MIRAGE — Malicious Intent Recognition and Adaptive Genuine Engagement

<p align="center">
  <img src="docs/figures/architecture_diagram.svg" alt="MIRAGE Banner" width="400px"/>
</p>

<p align="center">
  <strong>Malicious Intent Recognition and Adaptive Genuine Engagement</strong><br/>
  <em>A Research-Grade Stateful Adaptive Honeypot with ML Attack Classification and Closed-Loop Reinforcement Learning Deception.</em>
</p>

<p align="center">
  <a href="https://github.com/nayefsiddique-eng/Adaptive-Honeypot/actions/workflows/ci.yml"><img src="https://github.com/nayefsiddique-eng/Adaptive-Honeypot/actions/workflows/ci.yml/badge.svg" alt="CI status"/></a>
  <img src="https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python" alt="Python 3.12"/>
  <img src="https://img.shields.io/badge/FastAPI-0.137.1-green?style=flat-square&logo=fastapi" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/scikit--learn-1.9.0-orange?style=flat-square&logo=scikitlearn" alt="Scikit-Learn"/>
  <img src="https://img.shields.io/badge/XGBoost-3.3.0-red?style=flat-square&logo=xgboost" alt="XGBoost"/>
  <img src="https://img.shields.io/badge/License-MIT-purple?style=flat-square" alt="MIT License"/>
</p>

---

### Quick Navigation
[Overview](#overview) • [Core Capabilities](#core-capabilities) • [System Architecture](#system-architecture) • [Technical Modules](#technical-modules) • [Setup & Execution](#setup--execution) • [API Endpoint Reference](#api-endpoint-reference) • [ML Evaluation Metrics](#ml-evaluation-metrics) • [Roadmap](#roadmap) • [Citations](#citations)

---

## Overview

**MIRAGE** (Malicious Intent Recognition and Adaptive Genuine Engagement) is an advanced stateful adaptive honeypot designed to classify attacker activity and deploy matching deception layouts dynamically. Using an ensemble of machine learning models (Random Forest and XGBoost) for signature classification, an Isolation Forest for anomaly detection, and a Q-learning reinforcement learning engine, MIRAGE matches defenses directly to the attacker's skill level and tactics.

MIRAGE forms the deception core for **PRAETOR**, a capstone security engineering architecture designed to augment threat engagement with an explainable, policy-governed autonomous response layer.

---

## Core Capabilities

<table width="100%">
  <tr>
    <td width="50%">
      <h4>🛡️ Stateful Deception Profiles</h4>
      Exposes 8 distinct target configurations (e.g., <code>credential_trap</code>, <code>database_decoy</code>, <code>shell_trap</code>, <code>malware_sink</code>, <code>port_expansion</code>, <code>filesystem_decoy</code>, <code>web_decoy</code>, <code>default_monitor</code>) loaded with mock services, custom banners, custom delay loops, and decoy documents.
    </td>
    <td width="50%">
      <h4>🧠 Reinforcement Learning Q-Engine</h4>
      Applies Q-learning algorithms based on the Bellman equation to map incoming attacks, track intrusion session depths, and dynamically calculate reward feedback to select optimal deception postures session-over-session.
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h4>📊 Live Cyber-HUD Operation Cockpit</h4>
      A modular CSS-grid portal utilizing a futuristic theme. Features a 3D threat globe (Three.js) mapping geo markers (Leaflet.js) alongside Chart.js gauges tracking kill chain progressions.
    </td>
    <td width="50%">
      <h4>🕵️ Forensics & Keystroke Tracking</h4>
      Logs command line payloads and captures SHA-256 binary check hashes. Builds chronological attacker behavior timelines plotting session delta timing offsets.
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h4>📡 Threat Intelligence Feeds</h4>
      Queries visitor reputations on-the-fly against AbuseIPDB and AlienVault OTX servers, leveraging local caching to prevent API rate-limit bottlenecks.
    </td>
    <td width="50%">
      <h4>🤖 LLM Summary Reports</h4>
      Generates analyst-grade summary briefings detailing attacker activities, leveraging the Google Gemini API (cached in SQLite database).
    </td>
  </tr>
</table>

---

## System Architecture

```mermaid
flowchart TD
    subgraph Client Layer [Frontend Cyber-HUD]
        CL1[Three.js Threat Globe]
        CL2[SOC Metrics Dashboard]
        CL3[Forensics Timeline Player]
    end

    subgraph API Ingestion [FastAPI Server]
        R1[POST /api/logs/ingest]
        R2[GET /api/logs]
        R3[GET /api/research/metrics]
        R4[Asyncio Session Reaper]
    end

    subgraph Processing Pipeline [Core & Services]
        P1[Feature Extractor]
        P2[ML Ensemble Classifier]
        P3[GeoIP Enricher & Feeds]
        P4[RL Decision Engine]
    end

    subgraph Data Layer [Persistence]
        DB[(SQLAlchemy SQLite DB)]
    end

    CL1 & CL2 -->|Telemetry Queries| R2 & R3
    CL3 -->|Keystroke TIMELINE /api/sessions/id/timeline| R2
    
    R1 -->|1. Parse payload| P1
    P1 -->|2. Predict Class| P2
    P2 -->|3. GeoIP & Intel Check| P3
    P3 -->|4. Get Deception Score & select action| P4
    P4 -->|5. Write log & update profile| DB
    
    R4 -->|Reap idle sessions >15s| DB
    DB -->|Trigger Q-learning Bellman Updates| P4
```

---

## Technical Modules

* **`backend/main.py`**: FastAPIs startup engine. Spin-locks the **Asyncio Session Reaper** background thread which closes sessions idle for more than 15 seconds, attributing Bellman rewards and writing Q-values back to the database.
* **`backend/core/rl_engine.py`**: Houses the Q-learning policy loops. Resolves exploratory epsilon-greedy configurations, tracks state serialization hashes, and evaluates engagement durations and deception scores to reward the agent.
* **`backend/core/decision_engine.py`**: Stores configurations for the 8 stateful profiles, maintaining ports, mock file arrays, and delay times. Contains heuristics to match standard kill chain stages.
* **`backend/api/logs.py`**: Primary ingress point `/api/logs/ingest`. Validates network schemas, runs ML predictors, appends geolocation parameters, and interacts with the Q-learning engine before logging to SQLite.

---

## Setup & Execution

### 1. Clone & Initialize Environment
```bash
git clone https://github.com/nayefsiddique-eng/Adaptive-Honeypot.git
cd Adaptive-Honeypot
python -m venv venv
# On Windows
.\venv\Scripts\activate
# On Linux/macOS
source venv/bin/activate
```

### 2. Install Packages
```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Generate ML Pipeline Models
Generate the trained models and evaluate performance metrics:
```bash
python ml/train_classifier.py
python ml/evaluate_models.py
```

### 4. Boot the FastAPI Server
```bash
python -m uvicorn backend.main:app --port 8000
```
FastAPI Swagger documentation is accessible at `http://localhost:8000/docs`.

### 5. Launch the Traffic Attack Simulator
In a separate terminal, launch the closed-loop multi-step attacker simulation script:
```bash
python scripts/simulate_attacks.py --count 15 --delay 0.5 --session-delay 1.0
```

### 6. Start the Cyber-HUD Frontend
Open `frontend/index.html` directly in any web browser. It operates on `file://` protocol and queries the backend at `http://localhost:8000`.

---

## API Endpoint Reference

All endpoints are public and do not require authentication for research demonstrations.

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/` | API Health verification and honeypot active check. |
| `POST` | `/api/logs/ingest` | Logs raw traffic, extracts features, predicts class, geolocates, and queries the RL decision module. |
| `GET` | `/api/logs` | Fetch all logs (supports filter: `?ip={ip_address}`). |
| `POST` | `/api/decisions/evaluate` | Standard heuristic evaluation. |
| `POST` | `/api/decisions/evaluate_rl` | Dynamic reinforcement learning evaluation using Q-learning matrices. |
| `GET` | `/api/sessions` | Fetch all attacker session cards including chain statuses. |
| `GET` | `/api/sessions/{id}/behavior_timeline` | Reconstruct attacker delta-time event timeline for forensic logs. |
| `GET` | `/api/research/metrics` | Fetch IEEE evaluation data (contains cache hits, false-positives, latencies). |
| `GET` | `/api/research/learning-curve` | Get session sequential running average rewards tracking Q-convergence. |
| `POST` | `/api/admin/reset-demo` | Resets SQLite database tables (`honeypot.db`). |
| `POST` | `/api/admin/close-sessions` | Instantly close active sessions to trigger immediate learning updates. |

---

## ML Evaluation Metrics

Verified ML model performance metrics extracted from `ml/models/evaluation_results.json`:

| Model Classifier | Accuracy | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| **Random Forest** | 100.00% | 100.00% | 100.00% | 100.00% |
| **XGBoost** | 100.00% | 100.00% | 100.00% | 100.00% |
| **Isolation Forest** | 97.08% | 88.30% | 88.30% | 88.30% |

---

## Roadmap

```mermaid
mindmap
  root((MIRAGE Engine))
    MIRAGE (Built & Tested)
      Adaptive Deception (8 profiles)
      Machine Learning (Signature & Anomaly classification)
      Q-Learning RL Core (Dynamic behavior selection)
      Cyber-HUD Frontend (Command Center & SOC UI)
    PRAETOR (Future Development)
      Explainability Layer (Decisions rationalization)
      Autonomous Response (Policy-governed host blocks)
      Security Control Orchestrator
```

---

## Citations

If you use this system for academic work, please reference the working IEEE draft paper:

```bibtex
@ARTICLE{MIRAGE2026,
  author={Siddique, Nayef},
  journal={IEEE Transactions on Information Forensics and Security},
  title={MIRAGE: An Adaptive AI-Based Honeypot for Intelligent Cyber Threat Deception},
  year={2026},
  note={Under Review}
}
```