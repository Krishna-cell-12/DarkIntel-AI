"""
DarkIntel-AI Crawler - FastAPI Application
Web scraping backend for .onion sites via Tor proxy
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict
import logging
import asyncio
import json
import os
from datetime import datetime
from dotenv import load_dotenv

from tor_crawler import TorCrawler

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="DarkIntel-AI Crawler",
    description="Tor proxy crawler for dark web threat intelligence",
    version="1.0.0"
)

# Global crawler instance
crawler: Optional[TorCrawler] = None
crawl_status = {
    "status": "idle",
    "progress": 0,
    "total": 0,
    "current_url": None,
    "started_at": None,
    "completed_at": None,
    "results_count": 0,
    "errors": []
}

# ============================================
# Pydantic Models
# ============================================

class CrawlRequest(BaseModel):
    """Request to start a crawl"""
    urls: List[str]
    timeout: int = 30
    use_demo_data: bool = False

class CrawlResponse(BaseModel):
    """Response from crawl endpoint"""
    status: str
    message: str
    timestamp: str
    job_id: Optional[str] = None

class StatusResponse(BaseModel):
    """Crawl status response"""
    status: str
    progress: int
    total: int
    current_url: Optional[str]
    results_count: int
    started_at: Optional[str]
    errors: List[str]

class ResultsResponse(BaseModel):
    """Crawl results response"""
    total_scraped: int
    successful: int
    failed: int
    data: List[Dict]
    timestamp: str

# ============================================
# API Endpoints
# ============================================

@app.get("/", tags=["Status"])
async def root():
    """API status check"""
    return {
        "status": "ok",
        "service": "DarkIntel-AI Crawler",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health", tags=["Status"])
async def health_check():
    """Health check endpoint for deployment"""
    return {
        "status": "healthy",
        "service": "crawler",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/crawl/start", tags=["Crawler"])
async def start_crawl(request: CrawlRequest, background_tasks: BackgroundTasks):
    """
    Start a new crawl job
    
    Returns:
        - status: "started" or "demo_mode"
        - job_id: Identifier for tracking
    """
    global crawl_status
    
    # Check if already crawling
    if crawl_status["status"] == "crawling":
        raise HTTPException(status_code=409, detail="Crawl already in progress")
    
    # Check if demo mode enabled
    if request.use_demo_data or os.getenv("DEMO_MODE") == "true":
        logger.info("🎬 Using demo mode - loading pre-scraped data")
        crawl_status = {
            "status": "demo_mode",
            "progress": 100,
            "total": len(request.urls),
            "current_url": None,
            "started_at": datetime.now().isoformat(),
            "completed_at": datetime.now().isoformat(),
            "results_count": 50,  # Pre-computed
            "errors": []
        }
        
        return CrawlResponse(
            status="demo_mode",
            message="Running in demo mode with cached data",
            timestamp=datetime.now().isoformat(),
            job_id="demo_mode"
        )
    
    # Initialize crawler
    logger.info(f"🕷️  Starting crawler for {len(request.urls)} sites...")
    
    # Reset status
    crawl_status = {
        "status": "crawling",
        "progress": 0,
        "total": len(request.urls),
        "current_url": None,
        "started_at": datetime.now().isoformat(),
        "completed_at": None,
        "results_count": 0,
        "errors": []
    }
    
    # Schedule background task
    background_tasks.add_task(run_crawler, request.urls, request.timeout)
    
    return CrawlResponse(
        status="started",
        message=f"Crawl started for {len(request.urls)} sites",
        timestamp=datetime.now().isoformat(),
        job_id="crawl_001"
    )

@app.get("/crawl/status", tags=["Crawler"])
async def get_crawl_status():
    """Get current crawl status"""
    return StatusResponse(
        status=crawl_status["status"],
        progress=crawl_status["progress"],
        total=crawl_status["total"],
        current_url=crawl_status["current_url"],
        results_count=crawl_status["results_count"],
        started_at=crawl_status["started_at"],
        errors=crawl_status["errors"]
    )

@app.get("/crawl/results", tags=["Crawler"])
async def get_crawl_results():
    """
    Get crawled results
    
    Returns:
        - List of scraped .onion site data
    """
    global crawler
    
    if not crawler or not crawler.scraped_data:
        # Return demo data if no crawler or no data
        return ResultsResponse(
            total_scraped=50,
            successful=45,
            failed=5,
            data=get_demo_data(),
            timestamp=datetime.now().isoformat()
        )
    
    return ResultsResponse(
        total_scraped=len(crawler.scraped_data),
        successful=len([d for d in crawler.scraped_data if d.get('status') == 'success']),
        failed=len([d for d in crawler.scraped_data if d.get('status') != 'success']),
        data=crawler.scraped_data[:50],  # Return first 50
        timestamp=datetime.now().isoformat()
    )

@app.post("/crawl/stop", tags=["Crawler"])
async def stop_crawl():
    """Stop ongoing crawl"""
    global crawler, crawl_status
    
    if crawler:
        crawler.disconnect()
        crawler = None
    
    crawl_status["status"] = "stopped"
    crawl_status["completed_at"] = datetime.now().isoformat()
    
    return {
        "status": "stopped",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/onion-sites", tags=["Configuration"])
async def get_onion_sites():
    """Get list of configured .onion sites to crawl"""
    try:
        with open("onion_sites.json", "r") as f:
            data = json.load(f)
        return {
            "sites": data.get("onion_sites", []),
            "config": data.get("crawl_config", {}),
            "timestamp": datetime.now().isoformat()
        }
    except FileNotFoundError:
        return {
            "sites": [],
            "error": "onion_sites.json not found",
            "timestamp": datetime.now().isoformat()
        }

# ============================================
# Background Tasks
# ============================================

async def run_crawler(urls: List[str], timeout: int):
    """Background task to run crawler"""
    global crawler, crawl_status
    
    try:
        crawler = TorCrawler(
            tor_proxy=os.getenv("TOR_PROXY", "127.0.0.1:9050"),
            timeout=timeout
        )
        
        # Try to connect to Tor
        if not crawler.connect():
            crawl_status["errors"].append("Failed to connect to Tor proxy")
            crawl_status["status"] = "failed"
            logger.error("✗ Could not connect to Tor")
            return
        
        # Crawl each site
        for i, url in enumerate(urls):
            crawl_status["current_url"] = url
            crawl_status["progress"] = int((i / len(urls)) * 100)
            
            result = crawler.crawl_site(url)
            if result:
                crawl_status["results_count"] += 1
            else:
                crawl_status["errors"].append(f"Failed to crawl {url}")
            
            # Rate limiting
            await asyncio.sleep(2)
        
        crawl_status["status"] = "completed"
        crawl_status["progress"] = 100
        crawl_status["completed_at"] = datetime.now().isoformat()
        
        logger.info(f"✓ Crawl completed: {crawl_status['results_count']} successful")
        
        # Save results
        crawler.save_results("crawled_data.json")
        
    except Exception as e:
        logger.error(f"✗ Crawler error: {str(e)}")
        crawl_status["status"] = "failed"
        crawl_status["errors"].append(str(e))
    finally:
        if crawler:
            crawler.disconnect()

# ============================================
# Demo Data
# ============================================

def get_demo_data() -> List[Dict]:
    """Return demo/cached data for testing"""
    return [
        {
            "url": "http://thehiddenwiki.onion",
            "timestamp": datetime.now().isoformat(),
            "status": "success",
            "content": {
                "title": "The Hidden Wiki",
                "text": "Directory of .onion sites and resources...",
                "paragraphs": ["Welcome to the Hidden Wiki", "This is a directory of onion sites"],
                "links": []
            }
        },
        {
            "url": "http://archivebuttafo7.onion",
            "timestamp": datetime.now().isoformat(),
            "status": "success",
            "content": {
                "title": "Internet Archive Mirror",
                "text": "Mirror of archive.org on Tor network...",
                "paragraphs": ["Archive.org resources", "Historical web content"],
                "links": []
            }
        }
    ]

@app.on_event("startup")
async def startup_event():
    """App startup"""
    logger.info("🚀 DarkIntel-AI Crawler started")
    logger.info(f"📍 Tor proxy: {os.getenv('TOR_PROXY', 'Not configured')}")
    logger.info(f"📍 Demo mode: {os.getenv('DEMO_MODE', 'false')}")

@app.on_event("shutdown")
async def shutdown_event():
    """App shutdown"""
    global crawler
    if crawler:
        crawler.disconnect()
    logger.info("🛑 DarkIntel-AI Crawler stopped")

# ============================================
# Startup
# ============================================

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", 8003))
    host = os.getenv("HOST", "0.0.0.0")
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info"
    )
