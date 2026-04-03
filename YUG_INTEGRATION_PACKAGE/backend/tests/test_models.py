"""
Tests for Pydantic models
"""

import pytest
from pydantic import ValidationError
import sys
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent.parent.parent / "backend"
sys.path.insert(0, str(backend_path))

from orchestrator.models import (
    ThreatLevel, WalletRiskLevel, EntityType,
    ThreatMessage, WalletRiskScore, Entity,
    CrawlStatusResponse, ThreatAnalysisResponse,
    HealthCheckResponse, ConfigResponse,
    DashboardStats
)

class TestThreatLevel:
    """Test ThreatLevel enum"""
    
    def test_threat_levels_exist(self):
        """Test all threat levels are defined"""
        assert ThreatLevel.CRITICAL.value == "critical"
        assert ThreatLevel.HIGH.value == "high"
        assert ThreatLevel.MEDIUM.value == "medium"
        assert ThreatLevel.LOW.value == "low"
        assert ThreatLevel.INFO.value == "info"

class TestEntity:
    """Test Entity model"""
    
    def test_valid_entity(self):
        """Test creating valid entity"""
        entity = Entity(
            type=EntityType.WALLET_ADDRESS,
            value="0x123abc",
            confidence=0.95,
            context="Found in threat message"
        )
        assert entity.type == EntityType.WALLET_ADDRESS
        assert entity.value == "0x123abc"
        assert entity.confidence == 0.95

class TestThreatMessage:
    """Test ThreatMessage model"""
    
    def test_valid_threat_message(self):
        """Test creating valid threat message"""
        threat = ThreatMessage(
            id="threat_001",
            source_url="http://test.onion",
            content="Test threat",
            entities=[],
            threat_level=ThreatLevel.CRITICAL,
            threat_score=0.95,
            categories=["ransomware"],
            timestamp="2024-04-03T10:00:00"
        )
        assert threat.id == "threat_001"
        assert threat.threat_level == ThreatLevel.CRITICAL
        assert threat.threat_score == 0.95

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
