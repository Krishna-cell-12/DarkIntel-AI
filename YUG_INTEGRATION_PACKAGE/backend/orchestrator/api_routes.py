"""
API Routes for DarkIntel-AI Orchestrator
Endpoints for threat intelligence analysis pipeline
"""

from fastapi import APIRouter, BackgroundTasks, HTTPException
from datetime import datetime
from typing import List, Dict, Any
import logging

from .models import (
    CrawlRequest, CrawlStatusResponse, CrawlResultsResponse,
    ThreatAnalysisRequest, ThreatAnalysisResponse, ThreatMessage, Entity, ThreatLevel, EntityType,
    WalletAnalysisRequest, WalletAnalysisResponse, WalletRiskScore, WalletRiskLevel,
    ThreatEvent, ThreatEventEntity, ThreatIntelResponse,
    DashboardStats, DashboardData,
    HealthCheckResponse, ConfigResponse,
    StartAnalysisRequest, AnalysisPipelineStatus, AnalysisPipelineResults,
    OnionSite
)

logger = logging.getLogger(__name__)

# Create routers
crawler_router = APIRouter(prefix="/crawler", tags=["Crawler"])
threat_router = APIRouter(prefix="/threats", tags=["Threats"])
wallet_router = APIRouter(prefix="/wallets", tags=["Wallets"])
intel_router = APIRouter(prefix="/intel", tags=["Intelligence"])
dashboard_router = APIRouter(prefix="/dashboard", tags=["Dashboard"])
system_router = APIRouter(prefix="/system", tags=["System"])

# Global state
pipeline_tasks = {}
crawler_results = []
threat_results = []
wallet_results = []

# ============================================
# Crawler Routes
# ============================================

@crawler_router.post("/start")
async def start_crawler(request: CrawlRequest, background_tasks: BackgroundTasks):
    """Start dark web crawler"""
    logger.info(f"Starting crawler with demo_data={request.use_demo_data}")
    
    if request.use_demo_data:
        return {
            "status": "demo_mode",
            "message": "Using pre-computed demo data",
            "timestamp": datetime.now().isoformat()
        }
    
    return {
        "status": "started",
        "message": f"Crawler started for {len(request.urls or [])} sites",
        "timestamp": datetime.now().isoformat()
    }

@crawler_router.get("/status")
async def crawler_status():
    """Get crawler status"""
    return {
        "status": "idle",
        "progress": 0,
        "results_count": len(crawler_results),
        "timestamp": datetime.now().isoformat()
    }

@crawler_router.get("/results")
async def crawler_results_endpoint():
    """Get crawler results"""
    return {
        "total": len(crawler_results),
        "data": crawler_results[:50],
        "timestamp": datetime.now().isoformat()
    }

@crawler_router.get("/sites")
async def get_onion_sites():
    """Get list of configured .onion sites"""
    return {
        "sites": [
            {"id": 1, "url": "http://thehiddenwiki.onion", "name": "Hidden Wiki"},
            {"id": 2, "url": "http://archivebuttafo7.onion", "name": "Archive Mirror"},
            {"id": 3, "url": "http://3g2upl4pq6kufc4m.onion", "name": "DuckDuckGo"},
        ],
        "timestamp": datetime.now().isoformat()
    }

# ============================================
# Threat Analysis Routes
# ============================================

@threat_router.post("/analyze")
async def analyze_threats(request: ThreatAnalysisRequest):
    """Analyze threat messages for entities and threat level"""
    logger.info(f"Analyzing {len(request.messages)} threat messages")
    
    threats = []
    for i, message in enumerate(request.messages):
        threat = ThreatMessage(
            id=f"threat_{i}",
            source_url="http://example.onion",
            content=message,
            entities=extract_mock_entities(message),
            threat_level=ThreatLevel.HIGH,
            threat_score=0.85,
            categories=["ransomware", "credential_theft"],
            timestamp=datetime.now().isoformat()
        )
        threats.append(threat)
    
    return ThreatAnalysisResponse(
        analyzed_count=len(request.messages),
        threats_found=len([t for t in threats if t.threat_score > 0.5]),
        entities_extracted=sum(len(t.entities) for t in threats),
        messages=threats,
        timestamp=datetime.now().isoformat()
    )

@threat_router.get("/report")
async def threat_report():
    """Get threat analysis report"""
    return {
        "threats_analyzed": 150,
        "critical_threats": 5,
        "high_threats": 12,
        "entities_found": 48,
        "timestamp": datetime.now().isoformat()
    }

# ============================================
# Wallet Analysis Routes
# ============================================

@wallet_router.post("/analyze")
async def analyze_wallets(request: WalletAnalysisRequest):
    """Analyze cryptocurrency wallets for risk"""
    logger.info(f"Analyzing {len(request.addresses)} wallet addresses")
    
    wallets = []
    for i, address in enumerate(request.addresses):
        wallet = WalletRiskScore(
            address=address,
            risk_level=WalletRiskLevel.MEDIUM,
            score=0.65,
            factors=["high_volume", "mixed_activities"],
            balance=float(i * 10),
            activity_summary=None,
            timestamp=datetime.now().isoformat()
        )
        wallets.append(wallet)
    
    return WalletAnalysisResponse(
        analyzed_count=len(request.addresses),
        high_risk_found=1,
        wallets=wallets,
        timestamp=datetime.now().isoformat()
    )

@wallet_router.get("/high-risk")
async def get_high_risk_wallets():
    """Get list of high-risk wallets"""
    return {
        "high_risk_count": 5,
        "wallets": wallet_results[:10],
        "timestamp": datetime.now().isoformat()
    }

@wallet_router.get("/{address}")
async def get_wallet_details(address: str):
    """Get details for specific wallet"""
    return {
        "address": address,
        "balance": 10.5,
        "risk_level": "high",
        "transactions": 128,
        "timestamp": datetime.now().isoformat()
    }

# ============================================
# Intelligence Routes
# ============================================

@intel_router.post("/pipeline/start")
async def start_analysis_pipeline(request: StartAnalysisRequest, background_tasks: BackgroundTasks):
    """Start complete threat intelligence pipeline"""
    pipeline_id = f"pipeline_{datetime.now().timestamp()}"
    logger.info(f"Starting analysis pipeline {pipeline_id}")
    
    pipeline_tasks[pipeline_id] = {
        "status": "running",
        "created_at": datetime.now().isoformat(),
        "progress": 0
    }
    
    background_tasks.add_task(run_pipeline, pipeline_id, request)
    
    return {
        "pipeline_id": pipeline_id,
        "status": "started",
        "timestamp": datetime.now().isoformat()
    }

@intel_router.get("/pipeline/{pipeline_id}/status")
async def pipeline_status(pipeline_id: str):
    """Get analysis pipeline status"""
    if pipeline_id not in pipeline_tasks:
        raise HTTPException(status_code=404, detail="Pipeline not found")
    
    return AnalysisPipelineStatus(
        pipeline_id=pipeline_id,
        overall_status="completed",
        crawl_status="completed",
        analysis_status="completed",
        blockchain_status="completed",
        progress=100,
        results_count=50,
        errors=[],
        timestamp=datetime.now().isoformat()
    )

@intel_router.get("/pipeline/{pipeline_id}/results")
async def pipeline_results(pipeline_id: str):
    """Get analysis pipeline results"""
    return {
        "pipeline_id": pipeline_id,
        "threats_found": 12,
        "suspicious_wallets": 5,
        "entities_extracted": 48,
        "timestamp": datetime.now().isoformat()
    }

@intel_router.get("/summary")
async def threat_summary():
    """Get threat intelligence summary"""
    return {
        "total_threats": 150,
        "critical": 3,
        "high": 12,
        "medium": 35,
        "suspicious_wallets": 8,
        "total_volume_tracked": 1250.50,
        "last_updated": datetime.now().isoformat()
    }

# ============================================
# Dashboard Routes
# ============================================

@dashboard_router.get("/stats")
async def get_dashboard_stats():
    """Get dashboard statistics"""
    return DashboardStats(
        total_threats_analyzed=150,
        critical_threats=3,
        suspicious_wallets_found=8,
        total_volume_tracked=1250.50,
        last_crawl_time=datetime.now().isoformat(),
        crawler_status="idle"
    )

@dashboard_router.get("/data")
async def get_dashboard_data():
    """Get complete dashboard data"""
    return {
        "stats": {
            "total_threats": 150,
            "critical": 3,
            "high": 12
        },
        "recent_threats": [],
        "top_wallets": [],
        "timeline": [],
        "timestamp": datetime.now().isoformat()
    }

@dashboard_router.get("/threat-timeline")
async def threat_timeline():
    """Get threat timeline for visualization"""
    return {
        "timeline": [
            {"date": "2024-04-01", "count": 5, "level": "high"},
            {"date": "2024-04-02", "count": 8, "level": "critical"},
            {"date": "2024-04-03", "count": 3, "level": "medium"},
        ],
        "timestamp": datetime.now().isoformat()
    }

# ============================================
# System Routes
# ============================================

@system_router.get("/health")
async def health_check():
    """System health check"""
    return HealthCheckResponse(
        status="healthy",
        service="orchestrator",
        crawler_status="ready",
        nlp_status="ready",
        blockchain_status="ready",
        timestamp=datetime.now().isoformat(),
        uptime_seconds=3600.0
    )

@system_router.get("/config")
async def system_config():
    """Get system configuration"""
    return ConfigResponse(
        demo_mode=True,
        tor_enabled=False,
        api_keys_configured=True,
        modules={
            "crawler": True,
            "nlp": True,
            "blockchain": True
        },
        timestamp=datetime.now().isoformat()
    )

@system_router.get("/status")
async def system_status():
    """Get overall system status"""
    return {
        "status": "operational",
        "modules": {
            "crawler": "running",
            "nlp": "running",
            "blockchain": "running"
        },
        "timestamp": datetime.now().isoformat()
    }

# ============================================
# Helper Functions
# ============================================

def extract_mock_entities(text: str) -> List[Entity]:
    """Extract entities from text (mock implementation)"""
    entities = []
    
    # Mock wallet detection
    if "wallet" in text.lower() or "address" in text.lower():
        entities.append(Entity(
            type=EntityType.WALLET_ADDRESS,
            value="0x1234567890abcdef",
            confidence=0.85,
            context="Found in threat message"
        ))
    
    # Mock email detection
    if "@" in text:
        entities.append(Entity(
            type=EntityType.EMAIL,
            value="attacker@example.com",
            confidence=0.90,
            context="Email address found"
        ))
    
    return entities

async def run_pipeline(pipeline_id: str, request: StartAnalysisRequest):
    """Background task to run analysis pipeline"""
    try:
        logger.info(f"Running pipeline {pipeline_id}")
        
        # Update status
        pipeline_tasks[pipeline_id]["status"] = "completed"
        pipeline_tasks[pipeline_id]["progress"] = 100
        
        logger.info(f"Pipeline {pipeline_id} completed")
        
    except Exception as e:
        logger.error(f"Pipeline error: {str(e)}")
        pipeline_tasks[pipeline_id]["status"] = "failed"
