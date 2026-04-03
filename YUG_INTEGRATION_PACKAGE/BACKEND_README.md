# DarkIntel-AI Backend

Automated threat intelligence platform backend combining dark web crawling, AI analysis, and blockchain forensics.

## Architecture

```
backend/
├── crawler/              # .onion site crawler module
│   ├── main.py          # FastAPI app for crawler
│   ├── tor_crawler.py   # Tor proxy + scraping logic
│   ├── onion_sites.json # List of tested .onion URLs
│   └── requirements.txt  # Dependencies
│
└── orchestrator/         # Main orchestrator & API
    ├── main.py          # FastAPI orchestrator app
    ├── api_routes.py    # All API endpoints
    ├── models.py        # Pydantic schemas
    └── demo_mode.py     # Cached data management
```

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set Environment Variables

```bash
# Copy example config
copy YUG\.env.example YUG\.env

# Edit .env and add your API keys
# nano YUG\.env
```

**Required API Keys** (from [API_SETUP_GUIDE.md](../API_SETUP_GUIDE.md)):
- `GROQ_API_KEY` - For threat analysis
- `ALCHEMY_API_KEY` - For blockchain intelligence
- `ETHERSCAN_API_KEY` - Backup blockchain data

### 3. (Optional) Set Up Tor Proxy

For live dark web crawling:

```bash
# On Windows with Docker
docker run -d -p 9050:9050 dperson/torproxy

# Verify connection
curl --socks5 127.0.0.1:9050 http://check.torproject.org
```

### 4. Run Backend

**Option A: Demo Mode** (recommended for testing)
```bash
# Set DEMO_MODE=true in .env
uvicorn backend.orchestrator.main:app --reload --port 8000
```

**Option B: Live Mode** (requires API keys and Tor)
```bash
# Set DEMO_MODE=false in .env
# Ensure Tor proxy is running
uvicorn backend.orchestrator.main:app --reload --port 8000
```

### 5. Access API

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/health

## API Endpoints

### Crawler (`/crawler`)
- `POST /crawler/start` - Start crawling .onion sites
- `GET /crawler/status` - Get crawl progress
- `GET /crawler/results` - Get scraped data
- `GET /crawler/sites` - List configured sites
- `POST /crawler/stop` - Stop ongoing crawl

### Threats (`/threats`)
- `POST /threats/analyze` - Analyze threat messages
- `GET /threats/report` - Get threat report

### Wallets (`/wallets`)
- `POST /wallets/analyze` - Analyze crypto wallet risks
- `GET /wallets/high-risk` - Get high-risk wallets
- `GET /wallets/{address}` - Get wallet details

### Intelligence (`/intel`)
- `POST /intel/pipeline/start` - Start complete analysis
- `GET /intel/pipeline/{id}/status` - Get pipeline status
- `GET /intel/pipeline/{id}/results` - Get pipeline results
- `GET /intel/summary` - Get threat summary

### Dashboard (`/dashboard`)
- `GET /dashboard/stats` - Get statistics
- `GET /dashboard/data` - Get dashboard data
- `GET /dashboard/threat-timeline` - Get timeline

### System (`/system`)
- `GET /system/health` - Health check
- `GET /system/config` - System configuration
- `GET /system/status` - System status

### Demo (`/demo`) - Demo mode only
- `GET /demo/dashboard` - Complete demo dashboard
- `GET /demo/crawled-messages` - Demo crawled data
- `GET /demo/threat-analysis` - Demo threat analysis
- `GET /demo/wallet-risks` - Demo wallet risks
- `GET /demo/threat-events` - Demo threat events

## Features

### ✅ Implemented

1. **Tor Crawler Module**
   - SOCKS5 proxy integration
   - .onion site scraping
   - HTML parsing & content extraction
   - Rate limiting (2s delay between requests)
   - Error handling & retry logic
   - JSON result export

2. **FastAPI Orchestrator**
   - RESTful API with comprehensive endpoints
   - Pydantic models for type safety
   - Background task support
   - CORS middleware
   - Request/response logging

3. **Demo Mode**
   - 50 pre-scraped threat messages
   - 5 analyzed critical threats
   - 30 wallet risk assessments
   - Complete threat events (crawl → analysis → blockchain)
   - Instant zero-latency responses

4. **API Documentation**
   - Swagger UI (/docs)
   - ReDoc (/redoc)
   - OpenAPI schema (/openapi.json)

### 🔄 In Progress / Team Modules

- **NLP Module** (Atharva) - Entity extraction, threat scoring
- **Blockchain Module** (Yadnesh) - Wallet risk analysis, Alchemy integration
- **Frontend** (Krishna) - Dashboard UI, real-time visualization

## Demo Mode

Demo mode allows instant testing without:
- Tor connectivity
- API keys
- Live blockchain data

50+ pre-computed threat scenarios covering:
- Data breaches
- Ransomware operations
- Exploit code releases
- Credential leaks
- Malware distribution
- Wallet risk profiles

**Toggle Demo Mode**:
```python
# In .env
DEMO_MODE=true  # Use demo data (default)
DEMO_MODE=false # Use live APIs (requires setup)
```

**Demo Endpoints**:
```bash
# Get complete demo dashboard
curl http://localhost:8000/demo/dashboard

# Get demo crawled messages
curl http://localhost:8000/demo/crawled-messages

# Get demo threat analysis
curl http://localhost:8000/demo/threat-analysis

# Get demo wallet risks
curl http://localhost:8000/demo/wallet-risks
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEMO_MODE` | `true` | Enable demo mode (cached data) |
| `HOST` | `0.0.0.0` | Server host |
| `PORT` | `8000` | Server port |
| `TOR_PROXY` | `127.0.0.1:9050` | Tor SOCKS proxy address |
| `TOR_ENABLED` | `false` | Enable Tor crawling |
| `CORS_ORIGINS` | `http://localhost:5173` | Allowed frontend origins |
| `LOG_LEVEL` | `INFO` | Logging level |
| `GROQ_API_KEY` | (required) | Groq API key for NLP |
| `ALCHEMY_API_KEY` | (required) | Alchemy API key |
| `ETHERSCAN_API_KEY` | (required) | Etherscan API key |

## Deployment

### Local Development

```bash
uvicorn backend.orchestrator.main:app --reload --host 0.0.0.0 --port 8000
```

### Production (Railway)

1. Set environment variables in Railway dashboard
2. Ensure Python 3.10+ is selected
3. Set start command: `uvicorn backend.orchestrator.main:app --host 0.0.0.0 --port 8000`

### Docker

```bash
# Build image
docker build -t darkintel-ai-backend .

# Run container
docker run -p 8000:8000 -e DEMO_MODE=true darkintel-ai-backend
```

## Testing

### Quick Test

```bash
# Health check
curl http://localhost:8000/health

# Get demo dashboard
curl http://localhost:8000/demo/dashboard

# Start crawler
curl -X POST http://localhost:8000/crawler/start \
  -H "Content-Type: application/json" \
  -d '{"urls": [], "use_demo_data": true}'
```

### Run Tests

```bash
pytest backend/tests/ -v
```

## Troubleshooting

### Tor Connection Fails
- Ensure Docker is running: `docker ps | grep torproxy`
- Test Tor directly: `curl --socks5 127.0.0.1:9050 http://check.torproject.org`
- Check proxy in .env: `TOR_PROXY=127.0.0.1:9050`

### API Keys Missing
- Get keys from [API_SETUP_GUIDE.md](../API_SETUP_GUIDE.md)
- Add to .env: `GROQ_API_KEY=...`, `ALCHEMY_API_KEY=...`
- Restart server after changes

### Port Already in Use
```bash
# Find process using port 8000
lsof -i :8000

# Kill process
kill -9 <PID>
```

### Demo Data Not Loading
- Check `DEMO_MODE=true` in .env
- Verify demo_mode.py file exists
- Check logs for errors: `grep -i demo <logfile>`

## Performance Notes

- **Demo Mode**: ~50ms response time (cached data)
- **Live Crawling**: 30-120s depending on Tor network
- **Threat Analysis**: 2-5s per message (Groq API dependent)
- **Wallet Analysis**: 1-3s per wallet (Alchemy API dependent)

## Next Steps

1. **NLP Integration** - Receive analyzed threats from Atharva
2. **Blockchain Integration** - Receive wallet risks from Yadnesh
3. **Frontend Integration** - Connect to Krishna's React dashboard
4. **Deployment** - Deploy to Railway with live APIs
5. **Demo Video** - Record walkthrough for presentation

## Resources

- [Tor Project Documentation](https://www.torproject.org/docs/)
- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [Groq API Reference](https://console.groq.com/docs)
- [Alchemy API Reference](https://docs.alchemy.com/)
- [Etherscan API Reference](https://docs.etherscan.io/)

## Team

- **Yug** - Backend/Crawler (This module)
- **Krishna** - Frontend/UI
- **Atharva** - NLP/Threat Analysis
- **Yadnesh** - Blockchain/Wallet Analysis

---

**Last Updated**: April 3, 2024
**Status**: ✅ Priority 1 complete, Ready for Priority 2
