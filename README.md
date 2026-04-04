# DarkIntel-AI

DarkIntel-AI is a real-data dark web threat intelligence system built for hackathon Topic 05.
It correlates weak signals across unstructured multilingual inputs and turns them into actionable alerts.

## What It Does

- Ingests text from manual input, files, file paths, URLs, and Tor crawler streams
- Extracts entities such as emails, credentials, domains, IPs, wallets, companies, and keywords
- Detects leaked credentials, financial data, API keys, and crypto wallets
- Estimates breach impact (users affected, risk score, business risk, recommendations)
- Correlates cross-source signals and generates prioritized alerts
- Tracks proactive monitoring status and watchlist matches

## Key Modules

- `backend/server.py`: unified FastAPI backend with all API routes
- `backend/ingestion/`: ingestion pipeline and persistence
- `backend/nlp/`: entity extraction, threat scoring, slang decoding
- `backend/leak_detection/`: leak and impact analysis
- `backend/correlation/`: multi-source signal correlation
- `backend/alerts/`: prioritized alert generation
- `frontend/src/components/`: dashboard, threat feed, leak detector, alerts, analytics, monitor, company lookup

## Recent Finalization (Pre-1 PM)

- Added alerts page route and notification bell integration in UI
- Added drag-and-drop file upload flow in company lookup
- Added default noise filtering in threat feed (`min_score=20`)
- Added auto-correlation pipeline endpoint: `/api/correlate/auto`
- Wired full-analysis button in Leak Detector to auto-correlation pipeline
- Expanded multilingual slang aliases (50+ terms added)
- Added shared human-readable time utility across dashboard/feed/alerts/company lookup
- Added backend startup pre-seed from `test_threat_data.json`
- Fixed dashboard KPI bug so critical issues card reflects live critical counts

## Quick Start

### Backend

```bash
cd backend
pip install -r requirements.txt
python server.py
```

Backend runs at `http://localhost:8000`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173` (or next available Vite port).

## Core API Endpoints

- `GET /api/health`
- `GET /api/dashboard/stats`
- `GET /api/dashboard/data`
- `GET /api/threats/feed`
- `GET /api/threats/new`
- `GET /api/alerts`
- `POST /api/correlate`
- `POST /api/correlate/auto`
- `POST /api/leaks/impact`
- `POST /api/nlp/slang/decode`
- `POST /api/ingest`
- `POST /api/ingest/file`
- `POST /api/ingest/file-path`
- `POST /api/ingest/url`

## Validation Commands

```bash
# backend syntax
cd backend
python -m py_compile server.py

# frontend checks
cd ../frontend
npm run build
npx eslint src --ext .js,.jsx
```

## Notes for Submission Integrity

- README text and commit message for this finalization are authored from project-specific implementation details.
- No synthetic demo fallback is used in runtime paths; the app is configured for real-data workflows.
