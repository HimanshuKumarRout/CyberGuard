# CYBERGUARD — Frontend SOC Command Center

Modern, high-performance **Security Operations Center (SOC) Command Center** and triage dashboard built with React 18 and Vite.

---

## 🎨 Visual Design System & Aesthetics

CYBERGUARD is engineered to emulate elite, mission-critical cybersecurity operations centers:

- **Deep Space Cyber Palette:** Built upon obsidian black (`#080b11`), slate panels (`#0f172a`), and elevated frosted glass surfaces (`#1e293b`).
- **Glassmorphism & Depth:** Frosted glass panels with `backdrop-filter: blur(12px)` and subtle glowing borders.
- **Living Telemetry:** Real-time pulse animations (`.status-pulse-green`), dynamic radar status badges, and sub-millisecond indicator feedback.
- **Curated Typography:** Modern typography from Google Fonts:
  - **Interface Font:** `Inter` (optimal for dense data tables and telemetry).
  - **Display / Headers:** `Outfit` (clean geometric cyber aesthetic).
  - **Hashes & Telemetry:** `JetBrains Mono` (hashes, IP addresses, JSON objects).

### Semantic Severity Color Tokens

| Severity | Color Token | Hex Code | Visual Indicator |
|---|---|---|---|
| **Safe** | `--threat-safe` | `#10b981` | Emerald green aura |
| **Low** | `--threat-low` | `#0ea5e9` | Sky blue accent |
| **Medium** | `--threat-medium` | `#f59e0b` | Amber caution border |
| **High** | `--threat-high` | `#f97316` | Vibrant orange alert |
| **Critical** | `--threat-critical` | `#ef4444` | Crimson red with active pulse |

---

## 📂 Architecture & Directory Structure

```
frontend/
├── src/
│   ├── components/                 # Modular SOC presentation components
│   │   ├── common/                 # KpiCard, RiskGauge, LoadingFallback
│   │   ├── incident/               # IncidentDetailModal analyst portal
│   │   ├── navigation/             # Sticky Header & quick-switch Sidebar
│   │   ├── threat/                 # ExplainabilityCard (XAI evidence & narrative)
│   │   └── timeline/               # AttackTimeline time-series visualization
│   ├── constants/
│   │   └── theme.js                # Design tokens, severity colors & MITRE dictionary
│   ├── context/                    # Centralized React Context Providers
│   │   ├── AuthContext.jsx         # User sessions, JWT credentials & auth helpers
│   │   └── SocDataContext.jsx      # Telemetry, events, incidents & action handlers
│   ├── layouts/                    # Layout wrappers
│   │   └── MainLayout.jsx          # Protected workspace shell (Header + Sidebar + Outlet)
│   ├── pages/                      # Domain-isolated route views
│   │   ├── auth/                   # Login & Signup authentication views
│   │   ├── dashboard/              # Command Center executive overview
│   │   ├── incidents/              # SOC incident triage queue & resolution
│   │   ├── intel/                  # Interactive MITRE ATT&CK matrix
│   │   ├── models/                 # AI detector benchmarks & latency telemetry
│   │   └── studio/                 # Threat ingestion & simulation console
│   ├── routes/                     # Modular Routing Layer (React Router v7)
│   │   ├── guards/                 # ProtectedRoute session validation guard
│   │   ├── modules/                # Feature route definitions (auth, dashboard, etc.)
│   │   └── AppRoutes.jsx           # Root route composer & fallback handling
│   ├── services/
│   │   └── api.js                  # Centralized asynchronous API client
│   ├── App.jsx                     # Top-level context provider tree
│   ├── index.css                   # Global CSS design tokens & animations
│   └── main.jsx                    # React DOM entrypoint
├── package.json
└── vite.config.js                  # Dev server & reverse proxy configuration
```

---

## 🛠️ Key Modules & Screens

### 1. Command Center (`/pages/Dashboard.jsx`)
- **Metric Cards:** Total Ingested Events, Threats Detected, Critical P1 Alerts, Active Open Incidents.
- **Attack Timeline:** 24-hour visual distribution segmented by risk tier (`Safe`, `Medium`, `Critical`).
- **Live Event Feed:** Filterable, real-time telemetry stream showing detector classification and scores.

### 2. Threat Analysis Studio (`/pages/ThreatStudio.jsx`)
- **Multi-Source Ingestion Tabs:**
  - **Tab 1: Phishing & Malicious URLs:** Analyze RFC email headers, message text, and URLs.
  - **Tab 2: Digital Impersonation & Deepfakes:** Check VIP display names, spoofed webmail, and synthetic voice clips.
  - **Tab 3: Credential Theft & ATO:** Analyze login velocity, IP address, and burst failure counters.
- **1-Click Demo Presets:** Preloaded scenarios (PayPa1 Lookalike, CEO Wire BEC, Impossible Travel, Benign Corporate Email) for instantaneous live demonstrations.
- **XAI Decision Inspector:** Radial score gauge, quantifiable evidence points, contextual reasoning narrative, and safe simulation buttons.

### 3. Incident Management Hub (`/pages/Incidents.jsx`)
- Status filtering: `All`, `Open`, `In Investigation`, `Contained`, `Resolved`.
- Incident inspection modal with metadata, assigned analyst, timestamp, and containment action triggers.

### 4. MITRE ATT&CK Matrix (`/pages/ThreatIntel.jsx`)
- Interactive matrix mapping detected threats to standard MITRE Tactics (`Initial Access`, `Defense Evasion`, `Credential Access`) and Techniques (`T1566.002`, `T1586`, `T1110.003`, etc.).

### 5. Model Telemetry (`/pages/ModelPerformance.jsx`)
- Benchmarks for all active detectors: Precision, Recall, F1-Scores, p50 Latency, and p95 Latency.

---

## 🚀 Running Locally

### Development Mode
```bash
# Navigate to the frontend directory
cd frontend

# Install dependencies (if not already installed)
npm install

# Start development server with Hot Module Replacement (HMR)
npm run dev
```
The application will launch at `http://localhost:5173`.

### Production Build
```bash
npm run build
```
Creates an optimized static bundle in `frontend/dist/`.

### Preview Production Build
```bash
npm run preview
```

---

## 🔄 Backend API Proxying

The development server includes a built-in reverse proxy in `vite.config.js`:
```javascript
server: {
  port: 5173,
  proxy: {
    '/api': {
      target: 'http://127.0.0.1:8000',
      changeOrigin: true,
      secure: false,
    }
  }
}
```
All client API calls (`/api/...`) are automatically forwarded to the FastAPI backend running on port 8000, avoiding CORS conflicts.
