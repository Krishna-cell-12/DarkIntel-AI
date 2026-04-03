"""
Pytest configuration and fixtures
"""

import pytest
from fastapi.testclient import TestClient
import sys
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent.parent.parent / "backend"
sys.path.insert(0, str(backend_path))

# Import after path is set
from orchestrator.main import app

@pytest.fixture
def client():
    """Create test client"""
    return TestClient(app)

@pytest.fixture
def mock_crawler_data():
    """Mock crawler response data"""
    return {
        "url": "http://test.onion",
        "timestamp": "2024-04-03T10:00:00",
        "status": "success",
        "content": {
            "title": "Test Onion Site",
            "text": "Test content from .onion site",
            "paragraphs": ["Paragraph 1", "Paragraph 2"],
            "links": ["http://link1.onion", "http://link2.onion"]
        }
    }

@pytest.fixture
def mock_threat_data():
    """Mock threat analysis data"""
    return {
        "id": "threat_001",
        "source_url": "http://test.onion",
        "message": "Test threat message with wallet address 0x123abc",
        "threat_level": "critical",
        "threat_score": 0.95,
        "entities": [
            {
                "type": "wallet_address",
                "value": "0x123abc",
                "confidence": 0.92
            }
        ]
    }

@pytest.fixture
def mock_wallet_data():
    """Mock wallet risk data"""
    return {
        "address": "0x123abc",
        "risk_level": "critical",
        "score": 0.98,
        "balance": 125.45,
        "factors": ["mixer_detected", "high_velocity"]
    }
