# MIRAGE — Malicious Intent Recognition and Adaptive Genuine Engagement

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?style=flat-square&logo=fastapi)
![ML](https://img.shields.io/badge/ML-RandomForest%20|%20XGBoost%20|%20IsolationForest-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-purple?style=flat-square)

> A research-grade adaptive honeypot system that classifies attacker behavior in real time using an ML ensemble, dynamically reconfigures its deception environment based on attack type and attacker history, and generates AI-powered threat intelligence briefs.

---

## ML Model Benchmarks

| Model | Accuracy | Precision | Recall | F1-Score |
|---|---|---|---|---|
| Random Forest | 100.00% | 100.00% | 100.00% | 100.00% |
| XGBoost | 100.00% | 100.00% | 100.00% | 100.00% |
| Isolation Forest* | 97.08% | 88.30% | 88.30% | 88.30% |

*Isolation Forest evaluated on anomaly detection.

---

## Features

- ML Ensemble Classification — Random Forest + XGBoost with confidence scoring
- Isolation Forest Anomaly Detection — 88.3% recall on unknown traffic
- 8 Adaptive Deception Profiles — credential_trap, database_decoy, shell_trap, malware_sink, port_expansion, filesystem_decoy, web_decoy
- Session Recording — CLI command capture, payload SHA-256 hashing, interaction depth
- K-Means Attacker Clustering — script_kiddie / opportunist / targeted / advanced_persistent
- Dual Threat Intelligence — AbuseIPDB + AlienVault OTX
- GeoIP Enrichment — coordinates stored per log
- LLM Threat Summaries — Gemini API analyst-grade briefs per session
- Research Metrics API — detection rate, FP rate, adaptation effectiveness for IEEE evaluation
- MIRAGE SOC Dashboard — 9-section dark dashboard, Leaflet geo map, live attack feed

---

## Setup

### 1. Clone and create virtual environment
```bash
git clone https://github.com/nayefsiddique-eng/Adaptive-Honeypot.git
cd Adaptive-Honeypot
python -m venv venv
.\venv\Scripts\activate   # Windows
source venv/bin/activate    # Linux/macOS
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Train ML models
```bash
python ml/train_classifier.py
python ml/evaluate_models.py
```

### 4. Start backend
```bash
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### 5. Open dashboard
Open dashboard.html directly in any modern browser. No build step required.

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | / | Health check |
| POST | /api/logs/ingest | Ingest attack — runs full ML pipeline |
| GET | /api/logs/recent | Last 100 attack logs |
| POST | /api/decisions/evaluate | Get deception profile for attack + IP |
| GET | /api/decisions/profile/{type} | Static deception rules |
| GET | /api/dashboard | Aggregated dashboard telemetry |
| GET | /api/attacks/summary | Attack type counts + MITRE breakdown |
| GET | /api/attacks/top-ips | Top 10 IPs by attack volume |
| GET | /api/threat-intel/{ip} | AbuseIPDB + OTX + reputation score |
| GET | /api/timeline | Hourly and daily attack trends |
| GET | /api/sessions | All attacker sessions |
| GET | /api/sessions/clusters | K-Means attacker profiling |
| GET | /api/sessions/{id}/recording | Full event timeline + commands |
| GET | /api/sessions/{id}/summary | LLM threat brief |
| GET | /api/research/metrics | IEEE evaluation metrics |

---

## Research Metrics

| Metric | Description |
|---|---|
| Detection Rate | % of intrusions classified with confidence >= 50% |
| False Positive Rate | % of low-confidence events flagged incorrectly |
| Adaptation Effectiveness | % of sessions engaged in medium or high deception |
| Mean Response Time | API handling latency in milliseconds |

---

## Project Structure

```
adaptive-honeypot/
├── backend/
│   ├── api/          # FastAPI route handlers
│   ├── core/         # Feature extractor, adaptive engine, decision engine
│   ├── models/       # SQLAlchemy ORM models
│   ├── services/     # ML classifier, GeoIP, threat intel, LLM, clustering
│   └── main.py
├── ml/
│   ├── train_classifier.py
│   ├── evaluate_models.py
│   └── models/       # Trained .pkl files + evaluation_results.json
├── docs/figures/     # Architecture and flow diagrams
├── dashboard.html    # Single-file SOC dashboard
└── requirements.txt
```

---

## Citation

```bibtex
@ARTICLE{MIRAGE2026,
  author={Siddique, Nayef},
  journal={IEEE Transactions on Information Forensics and Security},
  title={MIRAGE: An Adaptive AI-Based Honeypot for Intelligent Cyber Threat Deception},
  year={2026},
  note={Under Review}
}
```