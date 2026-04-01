<div align="center">

# 🕵️ DarkIntel-AI

### AI-Powered Dark Web Threat Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-6-646CFF?logo=vite&logoColor=white)](https://vite.dev)
[![Groq](https://img.shields.io/badge/Groq-LLM-FF6B00?logo=data:image/svg+xml;base64,&logoColor=white)](https://groq.com)

*Real-time threat intelligence — NLP analysis, credential leak detection, dark web slang decoding, and identity linking.*

</div>

---

## 🚀 Features

| Module | Description |
|--------|-------------|
| **📊 Dashboard** | Real-time threat overview with severity distribution, live feed, and identity network graph |
| **🔍 Leak Detector** | Regex-based detection of credentials, credit cards, API keys, crypto wallets with impact estimation |
| **🔡 Slang Decoder** | Translates 80+ dark web slang terms with risk scoring using a curated cybercrime dictionary |
| **📰 Threat Feed** | NLP-analyzed threat intelligence feed with entity extraction and threat scoring |
| **🔗 Identity Linker** | Cross-platform identity correlation linking actors across dark web forums |
| **📈 Analytics** | Comprehensive visualizations — trend lines, severity heatmaps, and distribution charts |

## 🏗️ Architecture

```
DarkIntel-AI/
├── backend/                    # FastAPI server
│   ├── server.py               # Main API server (all endpoints)
│   ├── requirements.txt        # Python dependencies
│   ├── .env.example            # Environment template
│   ├── nlp/                    # NLP processing engine
│   │   ├── entity_extractor.py # Email, IP, wallet, CVE extraction
│   │   ├── slang_decoder.py    # Dark web terminology decoder
│   │   ├── threat_scorer.py    # Threat level scoring engine
│   │   └── precompute.py       # Batch entity pre-computation
│   └── leak_detection/         # Credential leak scanner
│       ├── credential_detector.py  # Regex-based secret detection
│       └── impact_estimator.py     # Risk & impact estimation
├── frontend/                   # React + Vite UI
│   ├── src/
│   │   ├── api.js              # API layer with backend integration
│   │   ├── App.jsx             # Root component with routing
│   │   ├── styles/             # Cyberpunk design system
│   │   │   ├── theme.css       # CSS variables, fonts, animations
│   │   │   └── components.css  # Reusable component styles
│   │   ├── components/         # UI components
│   │   │   ├── Dashboard.jsx   # Main dashboard with live feed
│   │   │   ├── LeakDetector.jsx    # Credential scanner UI
│   │   │   ├── SlangDecoder.jsx    # Slang translation UI
│   │   │   ├── ThreatFeed.jsx      # Threat list with filters
│   │   │   ├── IdentityLinker.jsx  # Network graph visualization
│   │   │   └── Analytics.jsx       # Charts & analytics
│   │   └── hooks/              # Custom React hooks
│   └── index.html
├── data/                       # Pre-computed analysis data
│   ├── synthetic_threats.json  # Sample threat corpus (50 entries)
│   └── precomputed_entities.json
└── YUG_INTEGRATION_PACKAGE/    # Tor crawler & orchestrator (expansion)
```

## ⚡ Quick Start

### Prerequisites

- **Python 3.10+**
- **Node.js 18+**
- **Groq API Key** → [Get one free at console.groq.com](https://console.groq.com)

### 1. Backend Setup

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your GROQ_API_KEY

# Start the server
python -c "import uvicorn; uvicorn.run('server:app', host='0.0.0.0', port=8000)"
```

The API will be available at `http://localhost:8000`. Verify with:
```bash
curl http://localhost:8000/api/health
```

### 2. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start dev server
npm run dev
```

The UI will be available at `http://localhost:5173`.

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check & service status |
| `GET` | `/api/dashboard/stats` | Dashboard statistics |
| `GET` | `/api/dashboard/data` | Full dashboard data payload |
| `GET` | `/api/threats/feed?limit=N` | Threat intelligence feed |
| `POST` | `/api/nlp/analyze` | Full NLP analysis (entities, threat score, slang) |
| `POST` | `/api/nlp/slang/decode` | Decode dark web slang terms |
| `GET` | `/api/nlp/slang/dictionary` | Full slang dictionary |
| `POST` | `/api/leaks/detect` | Scan text for credential leaks |
| `POST` | `/api/leaks/impact` | Leak detection + impact estimation |
| `POST` | `/api/leaks/identities` | Cross-platform identity linking |

### Example: Scan for Leaks

```bash
curl -X POST http://localhost:8000/api/leaks/impact \
  -H "Content-Type: application/json" \
  -d '{"text": "admin@corp.com:Password123\nAKIAIOSFODNN7EXAMPLE"}'
```

### Example: Decode Slang

```bash
curl -X POST http://localhost:8000/api/nlp/slang/decode \
  -H "Content-Type: application/json" \
  -d '{"text": "Got fresh logs and fullz for sale"}'
```

## 🎨 Design

The UI follows a **Cyberpunk Security Command Center** aesthetic:

- **Dark theme** with neon accents (Cyan `#00F0FF`, Magenta `#FF00E5`, Orange `#FF6B00`)
- **Glassmorphism** cards with backdrop blur
- **Monospace typography** (JetBrains Mono) for data display
- **CRT scanline** overlays and animated grid backgrounds
- **Animated counters**, donut charts, and SVG network graphs

## 🛡️ Detection Capabilities

The leak detector identifies:

- **Credentials** — `email:password` pairs with pattern matching
- **Credit Cards** — Visa, Mastercard, Amex with Luhn validation
- **API Keys** — AWS, Google, Stripe, GitHub tokens
- **Crypto Wallets** — Bitcoin (BTC), Ethereum (ETH), Monero (XMR)
- **PII** — SSNs, phone numbers, and more
- **80+ Dark Web Slang Terms** — with severity-weighted risk scoring

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 19, Vite 6, Vanilla CSS |
| **Backend** | FastAPI, Uvicorn, Pydantic |
| **AI/NLP** | Groq LLM API, Regex-based entity extraction |
| **Design** | Custom CSS design system, SVG visualizations |

## 📄 License

MIT License — Built for HackUp 2026
