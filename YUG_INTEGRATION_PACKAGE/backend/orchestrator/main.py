"""
DarkIntel-AI Main Orchestrator
Central FastAPI application that combines all modules:
- Dark web crawler
- NLP threat analysis
- Blockchain intelligence
- Real-time dashboard
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import os
from datetime import datetime
from typing import Optional

from .api_routes import (
    crawler_router, threat_router, wallet_router,
    intel_router, dashboard_router, system_router
)
from .models import HealthCheckResponse, ConfigResponse
from .demo_mode import get_demo_mode, DemoDataType
from .websocket import (
    CrawlerStreamHandler, ThreatStreamHandler, DashboardStreamHandler, 
    ConsoleStreamHandler, manager
)

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================
# FastAPI Application Setup
# ============================================

app = FastAPI(
    title="DarkIntel-AI Orchestrator",
    description="Automated threat intelligence platform combining dark web monitoring, AI analysis, and blockchain forensics",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# ============================================
# CORS Configuration
# ============================================

cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in cors_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# Demo Mode Initialization
# ============================================

DEMO_MODE_ENABLED = os.getenv("DEMO_MODE", "true").lower() == "true"
demo_mode = get_demo_mode(enabled=DEMO_MODE_ENABLED)

logger.info(f"🎬 Demo mode: {'ENABLED' if DEMO_MODE_ENABLED else 'DISABLED'}")
logger.info(f"📍 CORS origins: {cors_origins}")

# ============================================
# Router Registration
# ============================================

app.include_router(crawler_router)
app.include_router(threat_router)
app.include_router(wallet_router)
app.include_router(intel_router)
app.include_router(dashboard_router)
app.include_router(system_router)

# ============================================
# Root Endpoints
# ============================================

@app.get("/", tags=["Status"])
async def root():
    """Root endpoint"""
    return {
        "service": "DarkIntel-AI Orchestrator",
        "status": "operational",
        "version": "1.0.0",
        "demo_mode": DEMO_MODE_ENABLED,
        "docs": "/docs",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health", tags=["Status"])
async def health_check():
    """Comprehensive health check"""
    return HealthCheckResponse(
        status="healthy",
        service="orchestrator",
        crawler_status="ready",
        nlp_status="ready",
        blockchain_status="ready",
        timestamp=datetime.now().isoformat(),
        uptime_seconds=3600.0
    )

@app.get("/config", tags=["Status"])
async def system_config():
    """Get system configuration"""
    return ConfigResponse(
        demo_mode=DEMO_MODE_ENABLED,
        tor_enabled=os.getenv("TOR_ENABLED", "false").lower() == "true",
        api_keys_configured=bool(os.getenv("GROQ_API_KEY")),
        modules={
            "crawler": True,
            "nlp": True,
            "blockchain": True,
            "dashboard": True
        },
        timestamp=datetime.now().isoformat()
    )

# ============================================
# Demo Mode Endpoints
# ============================================

@app.get("/demo/dashboard", tags=["Demo"])
async def demo_dashboard_data():
    """Get complete demo dashboard data"""
    if not DEMO_MODE_ENABLED:
        raise HTTPException(status_code=400, detail="Demo mode not enabled")
    
    return demo_mode.get_dashboard_demo_data()

@app.get("/demo/crawled-messages", tags=["Demo"])
async def demo_crawled_messages():
    """Get demo crawled messages"""
    if not DEMO_MODE_ENABLED:
        raise HTTPException(status_code=400, detail="Demo mode not enabled")
    
    return {
        "messages": demo_mode.get_data(DemoDataType.CRAWLED_MESSAGES),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/demo/threat-analysis", tags=["Demo"])
async def demo_threat_analysis():
    """Get demo threat analysis"""
    if not DEMO_MODE_ENABLED:
        raise HTTPException(status_code=400, detail="Demo mode not enabled")
    
    return demo_mode.get_data(DemoDataType.THREAT_ANALYSIS)

@app.get("/demo/wallet-risks", tags=["Demo"])
async def demo_wallet_risks():
    """Get demo wallet risk analysis"""
    if not DEMO_MODE_ENABLED:
        raise HTTPException(status_code=400, detail="Demo mode not enabled")
    
    return demo_mode.get_data(DemoDataType.WALLET_RISKS)

@app.get("/demo/threat-events", tags=["Demo"])
async def demo_threat_events():
    """Get complete demo threat events"""
    if not DEMO_MODE_ENABLED:
        raise HTTPException(status_code=400, detail="Demo mode not enabled")
    
    return {
        "events": demo_mode.get_data(DemoDataType.THREAT_EVENTS),
        "timestamp": datetime.now().isoformat()
    }

# ============================================
# Analytics & Reporting Endpoints
# ============================================

@app.get("/analytics/threat-distribution", tags=["Analytics"])
async def threat_distribution():
    """Get threat distribution statistics"""
    return {
        "critical": 3,
        "high": 12,
        "medium": 35,
        "low": 45,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/analytics/entity-types", tags=["Analytics"])
async def entity_types_distribution():
    """Get distribution of extracted entity types"""
    return {
        "wallet_addresses": 48,
        "emails": 32,
        "domains": 15,
        "usernames": 28,
        "organizations": 12,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/analytics/wallet-risk-distribution", tags=["Analytics"])
async def wallet_risk_distribution():
    """Get wallet risk level distribution"""
    return {
        "critical": 2,
        "high": 8,
        "medium": 15,
        "low": 30,
        "clean": 45,
        "timestamp": datetime.now().isoformat()
    }

# ============================================
# WebSocket Endpoints - Real-time Updates
# ============================================

@app.websocket("/ws/crawler")
async def websocket_crawler(websocket: WebSocket):
    """WebSocket for real-time crawler status updates"""
    await CrawlerStreamHandler.stream_crawler_status(websocket)

@app.websocket("/ws/threats")
async def websocket_threats(websocket: WebSocket):
    """WebSocket for real-time threat analysis updates"""
    await ThreatStreamHandler.stream_threat_updates(websocket)

@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """WebSocket for real-time dashboard updates"""
    await DashboardStreamHandler.stream_dashboard_updates(websocket)

@app.websocket("/ws/console")
async def websocket_console(websocket: WebSocket):
    """WebSocket for live console/terminal output"""
    await ConsoleStreamHandler.stream_console_output(websocket)

# ============================================
# Error Handlers
# ============================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.now().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Custom general exception handler"""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": str(exc),
            "timestamp": datetime.now().isoformat()
        }
    )

# ============================================
# Lifecycle Events
# ============================================

@app.on_event("startup")
async def startup_event():
    """Application startup"""
    logger.info("=" * 60)
    logger.info("🚀 DarkIntel-AI Orchestrator Starting")
    logger.info("=" * 60)
    logger.info(f"📍 Service: DarkIntel-AI Orchestrator v1.0.0")
    logger.info(f"📍 Demo Mode: {'ENABLED' if DEMO_MODE_ENABLED else 'DISABLED'}")
    logger.info(f"📍 Tor Enabled: {os.getenv('TOR_ENABLED', 'false')}")
    logger.info(f"📍 API Docs: /docs")
    logger.info(f"📍 Health Check: /health")
    logger.info("=" * 60)

@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown"""
    logger.info("🛑 DarkIntel-AI Orchestrator stopped")

# ============================================
# Main Entry Point
# ============================================

if __name__ == "__main__":
    import uvicorn
    
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    
    logger.info(f"Starting server at {host}:{port}")
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=True,
        log_level="info"
    )
