"""
Pydantic Models for DarkIntel-AI API
Defines request/response schemas for all endpoints
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

# ============================================
# Enums
# ============================================

class ThreatLevel(str, Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class EntityType(str, Enum):
    """Entity types extracted from threat messages"""
    WALLET_ADDRESS = "wallet_address"
    EMAIL = "email"
    DOMAIN = "domain"
    PHONE = "phone"
    USERNAME = "username"
    ORGANIZATION = "organization"

class WalletRiskLevel(str, Enum):
    """Wallet risk classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CLEAN = "clean"

# ============================================
# Crawler Models
# ============================================

class OnionSite(BaseModel):
    """Onion site configuration"""
    id: int
    url: str
    name: str
    category: str
    description: str
    last_tested: str

class CrawlRequest(BaseModel):
    """Request to start crawling"""
    urls: Optional[List[str]] = None
    max_sites: int = 5
    timeout: int = 30
    use_demo_data: bool = False

class CrawledContent(BaseModel):
    """Crawled .onion site content"""
    url: str
    timestamp: str
    title: Optional[str]
    text: str
    paragraphs: List[str]
    links: List[str]

class CrawledItem(BaseModel):
    """Single crawled item"""
    url: str
    timestamp: str
    status: str
    content: CrawledContent

class CrawlStatusResponse(BaseModel):
    """Status of ongoing crawl"""
    status: str
    progress: int
    total: int
    current_url: Optional[str]
    results_count: int
    started_at: Optional[str]
    errors: List[str]

class CrawlResultsResponse(BaseModel):
    """Results from completed crawl"""
    total_scraped: int
    successful: int
    failed: int
    data: List[Dict]
    timestamp: str

# ============================================
# NLP/Entity Models
# ============================================

class Entity(BaseModel):
    """Extracted entity from threat message"""
    type: EntityType
    value: str
    confidence: float  # 0.0 - 1.0
    context: Optional[str]

class ThreatMessage(BaseModel):
    """Dark web threat message"""
    id: str
    source_url: str
    content: str
    entities: List[Entity]
    threat_level: ThreatLevel
    threat_score: float  # 0.0 - 1.0
    categories: List[str]  # e.g., ["ransomware", "data_breach", "credential_theft"]
    timestamp: str

class ThreatAnalysisRequest(BaseModel):
    """Request to analyze threat messages"""
    messages: List[str]
    extract_wallets: bool = True
    extract_entities: bool = True

class ThreatAnalysisResponse(BaseModel):
    """Response from threat analysis"""
    analyzed_count: int
    threats_found: int
    entities_extracted: int
    messages: List[ThreatMessage]
    timestamp: str

# ============================================
# Blockchain/Wallet Models
# ============================================

class WalletTransaction(BaseModel):
    """Single wallet transaction"""
    date: str
    amount: float
    from_address: str
    to_address: str
    type: str  # "in" or "out"

class WalletActivity(BaseModel):
    """Wallet activity summary"""
    total_transactions: int
    total_volume: float
    unique_counterparties: int
    first_activity: str
    last_activity: str
    recent_transactions: List[WalletTransaction]

class WalletRiskScore(BaseModel):
    """Risk score for a wallet"""
    address: str
    risk_level: WalletRiskLevel
    score: float  # 0.0 - 1.0
    factors: List[str]  # e.g., ["mixer_detected", "high_volume", "stolen_funds"]
    balance: float
    activity_summary: Optional[WalletActivity]
    timestamp: str

class WalletAnalysisRequest(BaseModel):
    """Request to analyze wallet addresses"""
    addresses: List[str]
    check_transactions: bool = True
    check_balance: bool = True

class WalletAnalysisResponse(BaseModel):
    """Response from wallet analysis"""
    analyzed_count: int
    high_risk_found: int
    wallets: List[WalletRiskScore]
    timestamp: str

# ============================================
# Aggregated Threat Intel Models
# ============================================

class ThreatEventEntity(BaseModel):
    """Entity with risk association"""
    type: str
    value: str
    confidence: float
    related_wallets: List[str]

class ThreatEvent(BaseModel):
    """Complete threat event from crawl → analysis → blockchain"""
    id: str
    source: str  # .onion URL
    message: str
    threat_level: ThreatLevel
    threat_score: float
    entities: List[ThreatEventEntity]
    associated_wallets: List[WalletRiskScore]
    timestamp: str
    tags: List[str]

class ThreatIntelResponse(BaseModel):
    """Complete threat intelligence response"""
    events: List[ThreatEvent]
    summary: Dict[str, Any]
    timestamp: str

# ============================================
# Dashboard Models
# ============================================

class DashboardStats(BaseModel):
    """Dashboard statistics"""
    total_threats_analyzed: int
    critical_threats: int
    suspicious_wallets_found: int
    total_volume_tracked: float
    last_crawl_time: Optional[str]
    crawler_status: str

class DashboardData(BaseModel):
    """Dashboard data for UI"""
    stats: DashboardStats
    recent_threats: List[ThreatEvent]
    top_wallets: List[WalletRiskScore]
    threat_timeline: List[Dict]
    entity_graph: Dict  # Relationships between entities

# ============================================
# System Models
# ============================================

class HealthCheckResponse(BaseModel):
    """Health check status"""
    status: str
    service: str
    crawler_status: str
    nlp_status: str
    blockchain_status: str
    timestamp: str
    uptime_seconds: float

class ConfigResponse(BaseModel):
    """System configuration"""
    demo_mode: bool
    tor_enabled: bool
    api_keys_configured: bool
    modules: Dict[str, bool]
    timestamp: str

class ErrorResponse(BaseModel):
    """Error response"""
    error: str
    code: int
    message: str
    timestamp: str

# ============================================
# Unified Request/Response Models
# ============================================

class StartAnalysisRequest(BaseModel):
    """Start complete dark web analysis pipeline"""
    crawl_urls: Optional[List[str]] = None
    use_demo_data: bool = False
    max_crawl_sites: int = 5
    analyze_threats: bool = True
    check_wallets: bool = True

class AnalysisPipelineStatus(BaseModel):
    """Status of the analysis pipeline"""
    pipeline_id: str
    overall_status: str  # "running", "completed", "failed"
    crawl_status: str
    analysis_status: str
    blockchain_status: str
    progress: int
    results_count: int
    errors: List[str]
    timestamp: str

class AnalysisPipelineResults(BaseModel):
    """Results from complete pipeline"""
    pipeline_id: str
    threats_found: int
    suspicious_wallets: int
    entities_extracted: int
    threat_events: List[ThreatEvent]
    high_risk_wallets: List[WalletRiskScore]
    dashboard_data: DashboardData
    timestamp: str
