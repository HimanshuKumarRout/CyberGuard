# CYBERGUARD — Backend API & Threat Detection Engine

The CYBERGUARD backend is a high-throughput, asynchronous cybersecurity intelligence and response engine built with **Python 3.11+**, **FastAPI**, and **Pydantic v2**.

---

## ⚡ The Canonical 7-Stage Pipeline

All threat artifacts flow through the mandatory sequential lifecycle:

```
[1. Ingestion] ➔ [2. Detection] ➔ [3. Classification] ➔ [4. Risk Assessment] ➔ [5. Explanation] ➔ [6. Alerting] ➔ [7. Recommended Response]
```

1. **Ingestion:** Normalizes raw email text, URL strings, synthetic media URLs, and authentication records into the **Unified Event Model (UEM)**.
2. **Detection:** Dispatches payloads to specialized domain detectors.
3. **Classification:** Categorizes attack taxonomy (e.g., `Lookalike Domain Spear-Phishing`, `Business Email Compromise (BEC)`, `Impossible Travel Anomaly`).
4. **Risk Assessment:** Synthesizes model confidence with deterministic indicator weights into a normalized $0 - 100$ score.
5. **Explanation:** Generates plain-language executive summaries, evidence vectors, and contextual reasoning narratives (Rule 1.3: Zero Naked Alerts).
6. **Alerting:** Automatically escalates events with $\text{Risk} \ge 60$ into SOC incident tickets.
7. **Recommended Response:** Recommends prioritized containment playbooks in safe simulation mode (Rule 1.4).

---

## 📂 Backend Architecture

```
backend/
├── app/
│   ├── api/
│   │   ├── endpoints.py     # FastAPI route handlers for analysis, triage, and telemetry
│   │   └── __init__.py
│   ├── db/
│   │   ├── schema.sql       # Relational schema DDL (PostgreSQL compatible)
│   │   ├── supabase.py      # Supabase Cloud Database client (PostgREST API)
│   │   └── __init__.py
│   ├── detectors/
│   │   ├── phishing.py      # Scenario 1: NLP text heuristics + Levenshtein / entropy engine
│   │   ├── impersonation.py # Scenario 2: Display name vs. header discrepancy + synthetic media
│   │   ├── anomaly.py       # Scenario 3: Great-circle Haversine velocity + brute-force counter
│   │   ├── orchestrator.py  # Threat Orchestrator routing and pipeline execution
│   │   └── __init__.py
│   ├── explain/
│   │   ├── explainer.py     # Explainable AI (XAI) engine (Rule 1.3 compliance)
│   │   └── __init__.py
│   ├── response/
│   │   ├── recommender.py   # Mitigation & safe containment simulation engine
│   │   └── __init__.py
│   ├── risk/
│   │   ├── scorer.py        # Calibrated hybrid risk scoring engine
│   │   └── __init__.py
│   ├── schemas/
│   │   ├── event.py         # Pydantic v2 Unified Event Model, Indicators, & Requests
│   │   └── __init__.py
│   ├── config.py            # Pydantic BaseSettings loading from .env
│   ├── main.py              # FastAPI application instance, CORS, & lifespan hooks
│   └── __init__.py
├── datasets/
│   └── demo_samples.json    # Curated evaluation datasets for all 3 scenarios
├── tests/
│   ├── test_pipeline.py     # Complete automated unit and integration test suite
│   └── __init__.py
└── requirements.txt         # Core dependencies
```

---

## 🎯 Threat Detection Modules

### 1. Scenario 1: Phishing & Malicious URL Detector (`phishing.py`)
- **Text NLP Heuristics:** Identifies urgency keywords, credential harvesting prompts, fear appeals, and authority exploitation.
- **Domain & URL Heuristics:**
  - Tokenized **Levenshtein edit distance** calculation against popular high-value brands (`paypal.com`, `microsoft.com`, `apple.com`, `amazon.com`, `google.com`).
  - **Shannon entropy** calculation for identifying randomized or DGA domain strings.
  - Identification of raw IP hosts, suspicious TLDs (`.xyz`, `.click`, `.top`, `.live`), and excessive subdomain nesting.

### 2. Scenario 2: Digital Impersonation & Deepfake Detector (`impersonation.py`)
- **VIP Executive Spoofing:** Compares claimed executive display names (CEO, CFO, CTO) against public webmail domains (`gmail.com`, `yahoo.com`, `outlook.com`).
- **Display Name Header Spoofing:** Identifies embedded email addresses in display names that mismatch the transmitting SMTP header.
- **Wire Fraud Pretext:** Scans for confidential wire transfer requests (Business Email Compromise).
- **Synthetic Media Heuristics:** Evaluates synthetic media cues and assigns authenticity scores.

### 3. Scenario 3: Credential Theft & ATO Anomaly Engine (`anomaly.py`)
- **Impossible Travel Velocity:** Implements the great-circle Haversine distance formula:
  $$V = \frac{\text{Distance}(\text{IP}_1, \text{IP}_2)}{\Delta t}$$
  Flags transitions $> 900\text{ km/h}$ as Critical anomalies.
- **Brute-Force Detection:** Tracks sliding-window consecutive failed authentication attempts ($\ge 5$ failures followed by access).
- **Novel Device Fingerprints:** Flags unfamiliar browser user-agents against baseline profiles.

---

## 🧮 Calibrated Hybrid Risk Scoring Formula

To prevent false alarms and unexplainable black-box verdicts, risk is calculated using a calibrated weighted formulation:

$$\text{Risk Score} = \min\left(100, \; (C_{\text{model}} \times 60) + (I_{\text{norm}} \times 40)\right)$$

Where:
- $C_{\text{model}} \in [0.0, 1.0]$: Continuous confidence emitted by the detector.
- $I_{\text{norm}} = \min\left(1.0, \sum \text{SeverityWeight}(\text{ind}_k)\right)$:
  - `Critical` Indicator: $+0.50$
  - `High` Indicator: $+0.35$
  - `Medium` Indicator: $+0.20$
  - `Low` Indicator: $+0.10$

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze/phishing` | Ingests text/URL and executes the Phishing detection pipeline |
| `POST` | `/api/analyze/impersonation` | Ingests sender metadata and checks for executive spoofing / deepfakes |
| `POST` | `/api/analyze/anomaly` | Ingests login telemetry and tests for impossible travel & brute-force |
| `GET` | `/api/events` | Lists paginated ingested events with filtering |
| `GET` | `/api/events/{id}` | Returns complete Unified Event Model detail including XAI rationale |
| `GET` | `/api/incidents` | Lists escalated SOC incidents by status |
| `PATCH` | `/api/incidents/{id}` | Updates incident lifecycle status (`Open`, `In Investigation`, `Contained`, `Resolved`) |
| `POST` | `/api/responses/execute` | Executes simulated containment action with non-repudiable audit logging |
| `GET` | `/api/dashboard/stats` | Retrieves top-level KPI counts (Total Events, Threats, Critical, Open) |
| `GET` | `/api/dashboard/timeline` | Returns time-series attack volume buckets |
| `GET` | `/api/models` | Returns model cards, benchmark latencies (p50/p95), and evaluation metrics |
| `GET` | `/api/health` | Health check endpoint |

---

## 🚀 Running the Backend Server

### Without Activating `.venv`:
From inside `backend/`:
```powershell
..\.venv\Scripts\python.exe run_backend.py
```
From the project root:
```powershell
.\.venv\Scripts\python.exe backend\run_backend.py
```

### With Activated `.venv`:
```powershell
python run_backend.py
```

---

## 🧪 Testing & Verification

Run the full pytest suite without activating `.venv` (from project root):
```powershell
.\.venv\Scripts\pytest -v
```
Or if `.venv` is activated:
```bash
pytest -v
```

All 8 tests validate schema instantiation, risk boundary edge cases, Levenshtein distance calculations, detector logic, explainability vectors, and the end-to-end 7-stage orchestrator pipeline.
