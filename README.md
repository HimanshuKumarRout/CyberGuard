# CYBERGUARD — AI-Powered Cyber Threat Detection & Response Platform

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5%2B-646CFF?logo=vite&logoColor=white)](https://vitejs.dev)
[![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063?logo=pydantic&logoColor=white)](https://docs.pydantic.dev/)
[![Tests](https://img.shields.io/badge/Tests-14%2F14%20Passing-10b981)](https://pytest.org)

**CYBERGUARD** is an institutional-grade, multi-layered cyber-defense and digital-trust platform. It bridges human-targeted psychological attacks (phishing, social engineering, executive impersonation, synthetic deepfakes) with system-level technical attacks (impossible travel velocity, brute-force spraying, credential theft, session deviations).

---

## ⚡ The Canonical 7-Stage Threat Processing Lifecycle

At the core of CYBERGUARD is an institutional-grade, deterministic threat processing lifecycle. Every raw input—whether an incoming email, suspicious URL, login telemetry log, or QR code—flows sequentially through **seven specialized stages**. Under CYBERGUARD engineering governance (Rule 1.1), no detector may bypass the Risk Scoring, Explainability, or Response stages.

```mermaid
flowchart TD
    subgraph S1 [Stage 1: Ingestion & Normalization]
        I1[Raw Payloads\nEmails, URLs, Auth Logs, Media] --> N1[Sanitizer & Envelope Validator]
        N1 --> UEM[Unified Event Model Envelope\nUEM Schema Contract]
    end

    subgraph S2 [Stage 2: Detection & Feature Extraction]
        UEM --> DET[Threat Orchestrator Router]
        DET --> D1[Phishing & URL Detector\nNLP Urgency, Levenshtein, Entropy]
        DET --> D2[Impersonation & Media Detector\nVIP Spoofing, BEC, Deepfakes]
        DET --> D3[Behavioral & ATO Detector\nHaversine Velocity, Brute Force]
    end

    subgraph S3 [Stage 3: Threat Classification]
        D1 & D2 & D3 --> CLS[Taxonomy & MITRE Mapping\nCategory, Attack Subtype, Confidence C_model]
    end

    subgraph S4 [Stage 4: Calibrated Risk Assessment]
        CLS --> RSK[Calibrated Hybrid Scoring Engine\nRisk = min 100, C_model x 60 + I_norm x 40]
        RSK --> BAND[5-Tier Risk Band\nSafe | Low | Medium | High | Critical]
    end

    subgraph S5 [Stage 5: Explainable AI Rationale]
        BAND --> XAI[Explainability Engine - Rule 1.3\nZero Naked Alerts Invariant]
        XAI --> EXP[Structured Rationale\n1. Summary Headline\n2. Quantified Evidence Points\n3. Contextual Reasoning Narrative]
    end

    subgraph S6 [Stage 6: Alerting & Incident Escalation]
        EXP --> TRG{Risk Score >= 60?}
        TRG -- Yes --> INC[Auto-Create SOC Incident\nP1/P2 Priority, Queue Assignment]
        TRG -- No --> TEL[Security Telemetry Logging]
        INC & TEL --> DB[(Supabase PostgreSQL\nevents, incidents, indicators, audit)]
    end

    subgraph S7 [Stage 7: Response & Safe Containment]
        INC & TEL --> RSP[Playbook Mitigation Recommender]
        RSP --> SIM[Safe Simulation Sandbox - Rule 1.4\nSimulated API Dispatch & Audit Trail]
        SIM --> ACT[Action Dispatch\nblock_url, quarantine_email, revoke_session]
    end
```

---

### Lifecycle Matrix Overview

| Stage | Name | Core Engine / Module | Primary Input | Primary Output | Architectural Invariant |
|---|---|---|---|---|---|
| **Stage 1** | **Ingestion & Normalization** | `UnifiedEventNormalizer`, `Validator` | Raw text, URLs, MIME, images, login logs | Initialized `UnifiedEvent` (UEM envelope) | **Rule 1.2: UEM Compliance** |
| **Stage 2** | **Detection & Feature Extraction** | `ThreatOrchestrator`, Domain Detectors | Normalized UEM payload & metadata | Extracted `Indicator` list & Model Confidence $C_{\text{model}}$ | Modular Detector Isolation |
| **Stage 3** | **Threat Classification** | Category Mappers, MITRE ATT&CK Matrix | Indicator vectors & feature vectors | Standardized `threat_category` & attack subtype | Strict Threat Taxonomy |
| **Stage 4** | **Risk Assessment** | `RiskScoringEngine` (`scorer.py`) | $C_{\text{model}} \in [0, 1]$ & `indicators` with weights | Normalized Score $[0, 100]$ & 5-tier `RiskLevel` | Deterministic Hybrid Scoring |
| **Stage 5** | **Explanation (XAI)** | `ExplainabilityEngine` (`explainer.py`) | Score, Tier, Indicators, Domain Metadata | `Explanation(summary, evidence, reasoning)` | **Rule 1.3: Zero Naked Alerts** |
| **Stage 6** | **Alerting & Escalation** | Event Router, Incident Dispatcher | Evaluated `UnifiedEvent` | Incident Ticket (`P1`/`P2`/`P3`) & DB persistence | Automated Threshold Triage ($\ge 60$) |
| **Stage 7** | **Recommended Response** | `ResponseEngine` (`recommender.py`) | Threat category, severity tier, target asset | Prioritized `ResponseAction` array & Audit Log | **Rule 1.4: Safe Simulation Sandbox** |

---

### Detailed Stage-by-Stage Breakdown

#### Stage 1: Ingestion & Normalization (Unified Event Model Envelope)
- **Objective:** Ingest disparate, multi-source digital artifacts into an immutable, universally parseable schema envelope.
- **Supported Input Modalities:**
  - **Email & Messaging:** RFC 822 / MIME headers, sender display names, reply-to fields, and message bodies.
  - **Web & Domain Artifacts:** Full URLs, query strings, redirect chains, and domain names.
  - **Multimedia & Physical:** Uploaded QR code images (Quishing), audio voice samples, and profile images.
  - **Authentication & Behavioral Logs:** User IDs, IPv4/IPv6 addresses, timestamp deltas, user-agent headers, and geocoordinates.
  - **Network & File Payloads:** PCAP capture metadata and file binary hashes.
- **Sanitization & Security Guarantees:**
  - Automated HTML tag sanitization and executable script stripping to prevent stored XSS or injection.
  - Payload length limits (e.g., maximum string buffers and image byte caps).
  - Normalization to UTC ISO-8601 timestamps and deterministic UUID generation (`evt_` prefix).
- **Output Contract (Rule 1.2 Compliance):**
  - Generates the standard `UnifiedEvent` schema envelope:
    ```json
    {
      "event_id": "evt_4f89d38c1a2e7b5f",
      "timestamp": "2026-11-02T14:47:32.180Z",
      "source": "email_gateway",
      "user_id": "usr_99182",
      "input_type": "email",
      "detector": "phishing_detector",
      "metadata": { "sender": "security-alert@office365-updates.xyz" }
    }
    ```

---

#### Stage 2: Feature Extraction & Multi-Modal Detection
- **Objective:** Execute domain-specific algorithms to extract deterministic security indicators and compute probabilistic ML model confidences.
- **Modular Dispatching:** The `ThreatOrchestrator` routes the normalized event to the appropriate domain engine:
  1. **Phishing & URL Detector (`phishing.py`):**
     - **NLP Psychological Triggers:** Identifies urgency triggers (*"within 24 hours"*, *"suspended immediately"*), authority exploitation (*"Compliance Officer"*, *"IT Helpdesk"*), and credential harvesting keywords.
     - **Levenshtein Distance Analysis:** Computes the minimal single-character edits required to transform the domain into high-value target brand domains:
       $$\text{lev}_{a,b}(i, j) = \begin{cases} \max(i,j) & \text{if } \min(i,j) = 0, \\ \min \begin{cases} \text{lev}_{a,b}(i-1, j) + 1 \\ \text{lev}_{a,b}(i, j-1) + 1 \\ \text{lev}_{a,b}(i-1, j-1) + 1_{(a_i \neq b_j)} \end{cases} & \text{otherwise} \end{cases}$$
       *Flags lookalike brand spoofing (e.g. `paypa1` $\rightarrow$ `paypal` has distance 1).*
     - **Shannon Entropy Analysis:** Computes domain lexical randomness to catch DGA (Domain Generation Algorithms) and obfuscated redirect subdomains:
       $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
       *Domains with $H(X) \ge 3.5$ are flagged for obfuscation.*
     - **Network Heuristics:** Flags raw IP address hosts (`http://192.168.1.5/login`) and suspicious top-level domains (`.xyz`, `.top`, `.tk`, `.ru`).
  2. **Impersonation & Media Detector (`impersonation.py`, `media.py`):**
     - **Display-Name Masquerading:** Matches executive VIP titles (e.g., *"CEO"*, *"CFO"*, *"VP Finance"*) originating from public webmail domains (`@gmail.com`, `@yahoo.com`, `@outlook.com`).
     - **Business Email Compromise (BEC):** Flags wire transfer prompts, invoice redirection, and confidential routing cues.
     - **Visual & Audio Heuristics:** Extracts QR barcode URLs from images (Quishing) and inspects Error Level Analysis (ELA) for image tampering.
  3. **Behavioral & ATO Detector (`anomaly.py`):**
     - **Impossible Travel Velocity:** Evaluates consecutive logins across geographic points using great-circle Haversine distance:
       $$d = 2R \arcsin\left(\sqrt{\sin^2\left(\frac{\Delta \phi}{2}\right) + \cos(\phi_1)\cos(\phi_2)\sin^2\left(\frac{\Delta \lambda}{2}\right)}\right)$$
       $$\text{Velocity} = \frac{d}{\Delta t} \quad (\text{km/h})$$
       *Transitions exceeding $900\text{ km/h}$ trigger an immediate Critical indicator.*
     - **Brute-Force Counter:** Evaluates failed authentication sequences within a sliding time window ($\ge 5$ consecutive failures).
     - **Device Fingerprint Drift:** Detects unfamiliar User-Agent combinations and novel IP subnet shifts.
- **Output Contract:** An array of structured `Indicator` objects and a calibrated confidence float $C_{\text{model}} \in [0.0, 1.0]$.

---

#### Stage 3: Threat Classification & Taxonomy Mapping
- **Objective:** Translate raw heuristic detections and model outputs into standardized threat classifications aligned with global cybersecurity frameworks.
- **Classification Taxonomies:**
  - **Phishing & Social Engineering:** `Credential Phishing`, `Lookalike Spear-Phishing`, `Quishing (QR Phishing)`, `Social Engineering`.
  - **Identity & Impersonation:** `Executive Impersonation (BEC)`, `Brand Masquerading`, `Synthetic Deepfake Media`.
  - **Account Compromise & Access:** `Account Takeover (ATO) - Impossible Travel`, `Brute-Force Credential Spraying`, `Session Anomaly`.
  - **Infrastructure & Malware:** `Malware / Ransomware C2`, `Network Port Scanning`, `Data Exfiltration`.
- **MITRE ATT&CK Matrix Alignment:**
  - Automatically tags events with corresponding MITRE tactics and techniques:
    - `T1566.001` — Phishing: Spearphishing Attachment / Link
    - `T1566.002` — Phishing: Spearphishing Service
    - `T1586.002` — Compromise Accounts: Email Accounts
    - `T1078.004` — Valid Accounts: Cloud Accounts
    - `T1110.001` — Brute Force: Password Guessing
- **Output Contract:** Populates the `threat_category` field and enriches the event metadata with MITRE tags.

---

#### Stage 4: Calibrated Hybrid Risk Assessment
- **Objective:** Eliminate opaque black-box AI scoring by binding probabilistic machine learning confidences with deterministic security heuristics.
- **The Calibrated Formula:**
  $$\text{Risk Score} = \min\left(100, \; \left(C_{\text{model}} \times 60\right) + \left(I_{\text{norm}} \times 40\right)\right)$$
  Where $C_{\text{model}}$ is the model confidence ($0.0 - 1.0$) and $I_{\text{norm}}$ is the normalized indicator sum:
  $$I_{\text{norm}} = \min\left(1.0, \; \sum_{k=1}^{M} W(\text{severity}_k)\right)$$
- **Indicator Weight Schedule ($W$):**
  - **Critical Severity:** $0.50$ (e.g., Levenshtein distance 1 to brand, travel velocity $>900\text{ km/h}$, raw IP host)
  - **High Severity:** $0.35$ (e.g., Urgency psychological cues, password harvesting prompts, $\ge 5$ brute force failures)
  - **Medium Severity:** $0.20$ (e.g., High Shannon entropy $\ge 3.5$, suspicious TLD, novel device profile)
  - **Low Severity:** $0.10$ (e.g., Unverified external sender tag, minor header variance)
- **5-Tier Risk Band Calibration:**

| Score Range | Risk Level | Operational Meaning | Automated Policy Action |
|---|---|---|---|
| **0 – 19** | `Safe` | Verified benign baseline. No threat indicators detected. | Allow uninterrupted; record baseline telemetry. |
| **20 – 39** | `Low` | Minor heuristic anomaly; negligible malicious probability. | Log informational record; silent background monitoring. |
| **40 – 59** | `Medium` | Ambiguous indicators; suspicious phrasing or atypical context. | Display visual warning banner to user/recipient. |
| **60 – 79** | `High` | Compelling malicious evidence; multiple compounding indicators. | Auto-create SOC Incident ticket; quarantine email/URL. |
| **80 – 100** | `Critical` | Confirmed high-consequence attack; critical indicators active. | Immediate SOC alert; simulate token revocation & host isolation. |

---

#### Stage 5: Explainable AI (XAI) Rationale Generation
- **Objective:** Provide human-readable, auditable, and non-repudiable justification for every verdict.
- **Rule 1.3 Invariant (Zero "Naked" Alerts):** Under CYBERGUARD governance, no system component may emit an alert that simply states *"Threat Detected"*. Every verdict ($Score \ge 20$) must deliver three mandatory pillars:
  1. **Executive Summary Headline:** A high-impact, plain-language assessment summarizing the verdict, score, and confidence.
     > *Example:* `"Critical Risk: Suspicious Lookalike Domain Spear-Phishing activity identified (Score: 95/100, Confidence: 92%)."`
  2. **Quantified Evidence Points:** An array of verifiable parameters citing exact values:
     - `"[Critical] Lookalike Domain: 'paypa1-security-login.com' mimics 'paypal.com' (edit distance: 1)"`
     - `"[Critical] Calculated travel velocity between logins: 1,842.6 km/h (Threshold: 900.0 km/h)"`
     - `"[High] Urgency Language: 'suspended within 24 hours'"`
     - `"[Medium] Domain Shannon entropy: 3.68 (Obfuscation threshold: 3.50)"`
  3. **Contextual Reasoning Narrative:** A coherent paragraph explaining how individual indicators compound into the final risk verdict:
     > *Example:* `"The convergence of multiple high-severity indicators and an AI model confidence of 92% justifies an escalated Critical verdict. Specifically, observable artifacts show evidence of lookalike domain, urgency language, credential request. Immediate containment action is recommended to mitigate active exploitation."`
- **Output Contract:** An `Explanation` schema object directly embedded in the `UnifiedEvent`.

---

#### Stage 6: Alerting, Incident Escalation & Persistence
- **Objective:** Escalate high-risk events to actionable operational queues and guarantee transactional persistence.
- **Automated Incident Escalation Criteria:**
  - If $\text{Risk Score} \ge 60$ (`High` or `Critical`), the `ThreatOrchestrator` automatically provisions a new record in the SOC Incident Queue.
  - Generates an `Incident` object with unique ID (`inc_`), associated `event_id`, descriptive title, and triage priority:
    - **P1 Priority:** Critical risk events ($\text{Score} \ge 80$). Immediate SOC analyst response required.
    - **P2 Priority:** High risk events ($60 \le \text{Score} < 80$). Response required within standard SLA window.
    - **P3 Priority:** Medium/informational records logged for threat hunting.
- **Incident State Lifecycle:**
  $$\text{Open} \longrightarrow \text{In Investigation} \longrightarrow \text{Contained} \longrightarrow \text{Resolved}$$
- **Multi-Table Relational Persistence (Supabase PostgreSQL):**
  - Transactionally commits events to `events`, extracted markers to `indicators`, rationale to `explanations`, and tickets to `incidents`.
  - Dispatches updates across real-time WebSockets and polling endpoints to synchronize the React SOC Command Center.

---

#### Stage 7: Automated Recommended Response & Safe Simulation
- **Objective:** Formulate prioritized containment recommendations and safely simulate mitigation workflows.
- **Rule 1.4 Invariant (Safe Simulation Guarantee):** During evaluations, demonstrations, and development, containment operations execute in **Simulated Mode**. Destructive OS commands or production network changes are never executed on host machines. Instead, structured external API representations (Okta, Cloudflare, Microsoft Graph, AWS IAM) are rendered and audited.
- **Playbook Mitigation Matrix:**

| Threat Category | Primary Target | Recommended Action (`action_type`) | Simulation Details & External API Dispatch |
|---|---|---|---|
| **Phishing / Quishing** | Malicious URL | `block_url` (P1) | Null-routes DNS via Cloudflare Gateway / Border Proxy |
| **Phishing / Impersonation** | Sender / Inbox | `quarantine_email` (P1) | Purges message from Exchange/M365 inboxes via Microsoft Graph |
| **Executive Spoofing** | Display Name | `flag_external_sender` (P2) | Adds prominent external impersonation warning banner |
| **Impossible Travel / ATO** | User Session | `revoke_session` (P1) | Invalidates active OAuth/OIDC tokens via Okta / Entra ID |
| **Brute Force / Password Spray** | Target Account | `force_password_reset` (P2) | Triggers step-up authentication and forces credential rotation |
| **Malware / Lateral Network** | IP / Host | `block_ip` / `isolate_host` (P1) | Provisions temporary border firewall drop rule and host quarantine |

- **Non-Repudiable Audit Trail:** Every triggered mitigation produces a record in the `audit_logs` table recording the initiating analyst, target resource, action type, execution timestamp, and simulated API payload.

---

### End-to-End Processing Flow Example

To illustrate the entire 7-stage lifecycle in action, consider an employee receiving a deceptive email:

```
[Raw Input]
Sender: "security-alert@office365-updates.xyz"
Subject: "CRITICAL: Office 365 Account Suspension Notice"
URL: "http://paypa1-security-login.com/auth"
Body: "Your corporate account will be suspended within 24 hours. Verify your password immediately."
   │
   ▼
[Stage 1: Ingestion] ────► Strips scripts, validates MIME structure, wraps into UnifiedEvent (evt_7a81c).
   │
   ▼
[Stage 2: Detection] ────► PhishingDetector NLP flags urgency & credential harvesting (conf = 0.92).
                          Domain analyzer flags Levenshtein dist = 1 to 'paypal' & entropy = 3.68.
   │
   ▼
[Stage 3: Classification] ► Classified as "Lookalike Domain Spear-Phishing" (MITRE T1566.002).
   │
   ▼
[Stage 4: Risk Scoring] ──► C_model = 0.92 (55.2 pts) + Indicators (0.50 + 0.35 + 0.35 = 1.0 -> 40 pts)
                          Total Risk Score = 95/100 -> Risk Level: Critical.
   │
   ▼
[Stage 5: XAI Rationale] ─► Generates 3-part Explanation with Summary, Quantified Evidence, and Reasoning.
   │
   ▼
[Stage 6: Alerting] ─────► Score 95 >= 60 -> Auto-provisions SOC Incident inc_3f92 (Priority P1).
                          Transactionally persisted in Supabase events & incidents tables.
   │
   ▼
[Stage 7: Response] ─────► ResponseEngine dispatches simulated P1 block_url & quarantine_email actions.
                          Logs non-repudiable entry in audit_logs table for compliance review.
```

---

## 🌟 Core System Highlights

### 1. The Three Mandatory Threat Scenarios

- **Scenario 1: Phishing & Malicious URL Detector**
  - **Text NLP Engine:** Detects urgency triggers, credential harvesting prompts, fear appeals, and authority exploitation.
  - **URL & Domain Heuristics:** Levenshtein edit distance against high-value target brands (`paypal.com`, `microsoft.com`, `apple.com`), domain Shannon entropy calculation, raw IP host identification, and suspicious TLD filtering.

- **Scenario 2: Digital Impersonation & Deepfake Detector**
  - **Identity Discrepancy Verification:** Checks display-name masquerading (e.g. VIP executive titles) originating from free public webmail domains (`gmail.com`, `yahoo.com`).
  - **Business Email Compromise (BEC):** Detects confidential wire transfer pretexts and display-name header spoofing.
  - **Synthetic Media Heuristics:** Flags multimedia frequency anomalies and computes authenticity confidence scores.

- **Scenario 3: Credential Theft & Behavioral ATO Engine**
  - **Impossible Travel Velocity:** Computes great-circle Haversine distance divided by elapsed time ($V = \frac{\text{Distance}}{\Delta t}$). Flags velocities $> 900\text{ km/h}$ as Critical anomalies.
  - **Brute-Force Counter:** Tracks sliding-window consecutive failed authentication attempts ($\ge 5$ failures).
  - **Novel Device Profiling:** Identifies unfamiliar device user-agent signatures.

---

### 2. Calibrated Hybrid Risk Scoring Engine

CYBERGUARD avoids black-box opacity by grounding scores with deterministic security indicators:

$$\text{Risk Score} = \min\left(100, \; (C_{\text{model}} \times 60) + (I_{\text{norm}} \times 40)\right)$$

| Score Range | Risk Level | Description | Automated Action |
|---|---|---|---|
| **0 – 19** | `Safe` | Normal, benign traffic. No malicious indicators found. | Log event; allow uninterrupted. |
| **20 – 39** | `Low` | Minor heuristic anomalies; low probability of maliciousness. | Log informational record; silent telemetry. |
| **40 – 59** | `Medium` | Ambiguous indicators; potential suspicious context. | Display visual warning banner to user. |
| **60 – 79** | `High` | Strong evidence of malicious intent; multiple severe indicators. | Auto-create SOC Incident; quarantine artifact. |
| **80 – 100** | `Critical` | Confirmed active attack; high confidence & critical indicators. | Immediate SOC alert; auto-simulate containment; revoke tokens. |

---

### 3. Explainable AI (XAI) — Rule 1.3: Zero "Naked" Alerts

Under CYBERGUARD engineering governance, no alert may simply state *"Threat Detected"*. Every verdict ($Score \ge 20$) includes:
1. **Executive Summary:** Plain-language high-impact assessment.
2. **Quantified Evidence Points:** Concrete parameters (e.g., Levenshtein distance, Shannon entropy score, travel velocity in km/h).
3. **Contextual Reasoning:** Cohesive narrative explaining how features compound into the verdict.

---

### 4. Safe Simulation Sandbox — Rule 1.4

Automated containment actions (e.g., domain blacklisting, token revocation, host quarantine) execute in **Simulated Mode** during prototypes and evaluation. Every action produces a structured entry in the audit stream showing what production API call (Okta, Cloudflare, Microsoft Graph) would be dispatched in live deployment.

---

## 📂 Repository Layout

```
CYBERGUARD/
├── backend/
│   ├── app/
│   │   ├── api/             # FastAPI REST endpoints
│   │   ├── auth/            # JWT authentication & password hashing
│   │   ├── db/              # Supabase Cloud client (PostgreSQL)
│   │   ├── detectors/       # Phishing, Impersonation & Anomaly detectors
│   │   ├── explain/         # Explainable AI (XAI) engine
│   │   ├── response/        # Containment & mitigation engine
│   │   ├── risk/            # Calibrated hybrid risk scoring engine
│   │   ├── schemas/         # Unified Event Model (UEM) Pydantic schemas
│   │   ├── config.py        # Settings & environment configuration
│   │   └── main.py          # FastAPI application entrypoint
│   ├── datasets/            # Curated demo scenarios (JSON)
│   ├── tests/               # Automated unit & integration tests
│   ├── README.md            # Backend-specific architecture & API documentation
│   └── requirements.txt     # Python dependencies
├── docs/                    # PRD, Architecture, Rules, Design, Roadmap & Extensions
├── frontend/                # React + Vite SOC Command Center
│   ├── src/
│   │   ├── components/      # Modular visual components
│   │   │   ├── common/      # KpiCard, RiskGauge, LoadingFallback
│   │   │   ├── incident/    # IncidentDetailModal
│   │   │   ├── navigation/  # Header, Sidebar
│   │   │   ├── threat/      # ExplainabilityCard (XAI)
│   │   │   └── timeline/    # AttackTimeline
│   │   ├── constants/       # Severity colors, risk tiers & MITRE mappings
│   │   ├── context/         # Centralized Auth & SOC Telemetry React Contexts
│   │   ├── layouts/         # Protected MainLayout shell
│   │   ├── pages/           # Domain-isolated page views
│   │   │   ├── auth/        # Login, Signup
│   │   │   ├── dashboard/   # Executive Command Center
│   │   │   ├── incidents/   # Incident Triage & Resolution
│   │   │   ├── intel/       # MITRE ATT&CK Matrix
│   │   │   ├── models/      # AI Model Telemetry & Benchmarks
│   │   │   └── studio/      # Interactive Threat Simulator
│   │   ├── routes/          # Modular routing layer (React Router v7)
│   │   │   ├── guards/      # ProtectedRoute auth guard
│   │   │   ├── modules/     # Feature route definitions (auth, dashboard, etc.)
│   │   │   └── AppRoutes.jsx# Dynamic route composition tree
│   │   ├── services/        # Asynchronous API client service
│   │   ├── App.jsx          # Top-level provider tree
│   │   ├── index.css        # Dark SOC cyber aesthetic tokens
│   │   └── main.jsx         # DOM entrypoint
│   ├── README.md            # Frontend-specific architecture & UI documentation
│   ├── package.json
│   └── vite.config.js       # Reverse proxy configuration
├── run_backend.py           # Convenience root launcher for backend
├── pytest.ini               # Pytest configuration
├── .env.example             # Environment configuration template
└── .gitignore
```

---

## 🚀 Quickstart Guide

### Prerequisites
- **Python 3.11+**
- **Node.js 18+ & npm**

### Terminal 1: Launch Backend Server

#### Option A: Run directly without activating `.venv` (Fastest)
From the project root:
```powershell
.\.venv\Scripts\python.exe backend\run_backend.py
```
Or if you navigated into `backend/`:
```powershell
cd backend
..\.venv\Scripts\python.exe run_backend.py
```

#### Option B: Activate `.venv` first
```powershell
# 1. Activate the Python virtual environment (from project root)
.\.venv\Scripts\Activate.ps1   # Windows PowerShell
# source .venv/bin/activate    # Linux / macOS

# 2. Start the FastAPI backend
python backend/run_backend.py
```

- **Backend API:** `http://127.0.0.1:8000`
- **Interactive Swagger Docs:** `http://127.0.0.1:8000/docs`

### Terminal 2: Launch Frontend Dashboard
```powershell
# 1. Navigate to the frontend directory
cd frontend

# 2. Start Vite development server
npm run dev
```
- **Command Center Dashboard:** `http://localhost:5173`

---

## 🧪 Automated Testing & Verification

Run the full pytest suite from the root directory without activating `.venv`:
```powershell
.\.venv\Scripts\pytest -v
```
Or if `.venv` is activated:
```powershell
pytest -v
```

All 14 tests validate:
- ✅ **UEM Compliance:** Pydantic schema validation for events, indicators, and actions.
- ✅ **Risk Engine:** Boundary clamping $[0, 100]$ and severity tier mapping.
- ✅ **Domain Heuristics:** Levenshtein edit distance and Shannon entropy metrics.
- ✅ **Scenario 1 Detector:** Lookalike brand domain and urgency keyword detection.
- ✅ **Scenario 2 Detector:** VIP executive display-name and public webmail discrepancy.
- ✅ **Scenario 3 Detector:** Impossible travel velocity calculation ($>900\text{ km/h}$).
- ✅ **Explainability Engine:** Zero naked alerts invariant (Summary + Evidence + Reasoning).
- ✅ **Orchestrator Pipeline:** Full 7-stage end-to-end execution.
- ✅ **Quishing Detector:** QR barcode payload extraction and malicious URL triage.
- ✅ **Academic & Gov Spoofing:** Educational/governmental impersonation vectors.
- ✅ **Malware Detection:** Suspicious file hashes, high entropy, and PE headers.
- ✅ **Network Traffic Analysis:** Port scan patterns, SYN flood, and lateral movement.
- ✅ **API Abuse & Exfiltration:** Abnormal token frequency and sensitive endpoint exfiltration.
- ✅ **Media ELA & Synthetic Audio:** Error Level Analysis compression artifacts and cloned voice pitch variance.

---

