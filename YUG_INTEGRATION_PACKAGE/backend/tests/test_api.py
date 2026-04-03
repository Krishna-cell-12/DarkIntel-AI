"""
Integration tests for DarkIntel-AI API endpoints
"""

import pytest
from fastapi.testclient import TestClient

class TestSystemEndpoints:
    """Test system health and status endpoints"""
    
    def test_root_endpoint(self, client):
        """Test root endpoint"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert data["service"] == "DarkIntel-AI Orchestrator"
        assert "version" in data
        assert "timestamp" in data
    
    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "orchestrator"
        assert "crawler_status" in data
        assert "nlp_status" in data
        assert "blockchain_status" in data
    
    def test_system_config(self, client):
        """Test system configuration endpoint"""
        response = client.get("/config")
        assert response.status_code == 200
        data = response.json()
        assert "demo_mode" in data
        assert "tor_enabled" in data
        assert "modules" in data
        assert isinstance(data["modules"], dict)

class TestCrawlerEndpoints:
    """Test crawler module endpoints"""
    
    def test_get_onion_sites(self, client):
        """Test getting list of onion sites"""
        response = client.get("/crawler/sites")
        assert response.status_code == 200
        data = response.json()
        assert "sites" in data
        assert isinstance(data["sites"], list)
        assert len(data["sites"]) > 0
        assert "url" in data["sites"][0]
    
    def test_get_crawler_status(self, client):
        """Test getting crawler status"""
        response = client.get("/crawler/status")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "progress" in data
        assert "results_count" in data
    
    def test_get_crawler_results(self, client):
        """Test getting crawler results"""
        response = client.get("/crawler/results")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data
        assert isinstance(data["data"], list)
    
    def test_start_crawler_demo_mode(self, client):
        """Test starting crawler in demo mode"""
        response = client.post("/crawler/start", json={
            "urls": [],
            "use_demo_data": True
        })
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ["started", "demo_mode"]

class TestThreatEndpoints:
    """Test threat analysis endpoints"""
    
    def test_threat_report(self, client):
        """Test getting threat report"""
        response = client.get("/threats/report")
        assert response.status_code == 200
        data = response.json()
        assert "threats_analyzed" in data
        assert "critical_threats" in data
        assert "entities_found" in data
    
    def test_analyze_threats(self, client):
        """Test analyzing threat messages"""
        response = client.post("/threats/analyze", json={
            "messages": ["Database leaked with 100k records"],
            "extract_wallets": True,
            "extract_entities": True
        })
        assert response.status_code == 200
        data = response.json()
        assert "analyzed_count" in data
        assert "threats_found" in data
        assert "messages" in data
        assert isinstance(data["messages"], list)

class TestWalletEndpoints:
    """Test wallet analysis endpoints"""
    
    def test_get_high_risk_wallets(self, client):
        """Test getting high-risk wallets"""
        response = client.get("/wallets/high-risk")
        assert response.status_code == 200
        data = response.json()
        assert "high_risk_count" in data
        assert "wallets" in data
    
    def test_analyze_wallets(self, client):
        """Test analyzing wallet addresses"""
        response = client.post("/wallets/analyze", json={
            "addresses": ["0x123abc", "0x456def"],
            "check_transactions": True,
            "check_balance": True
        })
        assert response.status_code == 200
        data = response.json()
        assert "analyzed_count" in data
        assert data["analyzed_count"] == 2
        assert "wallets" in data
    
    def test_get_wallet_details(self, client):
        """Test getting details for specific wallet"""
        response = client.get("/wallets/0x123abc")
        assert response.status_code == 200
        data = response.json()
        assert "address" in data
        assert data["address"] == "0x123abc"
        assert "balance" in data
        assert "risk_level" in data

class TestIntelligenceEndpoints:
    """Test threat intelligence endpoints"""
    
    def test_threat_summary(self, client):
        """Test getting threat summary"""
        response = client.get("/intel/summary")
        assert response.status_code == 200
        data = response.json()
        assert "total_threats" in data
        assert "critical" in data
        assert "high" in data
        assert "suspicious_wallets" in data
    
    def test_start_pipeline(self, client):
        """Test starting analysis pipeline"""
        response = client.post("/intel/pipeline/start", json={
            "use_demo_data": True,
            "analyze_threats": True,
            "check_wallets": True
        })
        assert response.status_code == 200
        data = response.json()
        assert "pipeline_id" in data
        assert "status" in data

class TestDashboardEndpoints:
    """Test dashboard endpoints"""
    
    def test_dashboard_stats(self, client):
        """Test getting dashboard statistics"""
        response = client.get("/dashboard/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_threats_analyzed" in data
        assert "critical_threats" in data
        assert "suspicious_wallets_found" in data
        assert "total_volume_tracked" in data
    
    def test_dashboard_data(self, client):
        """Test getting complete dashboard data"""
        response = client.get("/dashboard/data")
        assert response.status_code == 200
        data = response.json()
        assert "stats" in data
        assert "recent_threats" in data
        assert "top_wallets" in data
    
    def test_threat_timeline(self, client):
        """Test getting threat timeline"""
        response = client.get("/dashboard/threat-timeline")
        assert response.status_code == 200
        data = response.json()
        assert "timeline" in data
        assert isinstance(data["timeline"], list)

class TestDemoEndpoints:
    """Test demo mode endpoints"""
    
    def test_demo_dashboard(self, client):
        """Test demo dashboard endpoint"""
        response = client.get("/demo/dashboard")
        assert response.status_code == 200
        data = response.json()
        assert "stats" in data
        assert "recent_threats" in data
        assert "top_wallets" in data
    
    def test_demo_crawled_messages(self, client):
        """Test demo crawled messages"""
        response = client.get("/demo/crawled-messages")
        assert response.status_code == 200
        data = response.json()
        assert "messages" in data
        assert len(data["messages"]) > 0
    
    def test_demo_threat_analysis(self, client):
        """Test demo threat analysis"""
        response = client.get("/demo/threat-analysis")
        assert response.status_code == 200
        data = response.json()
        assert "threats" in data or "total_analyzed" in data
    
    def test_demo_wallet_risks(self, client):
        """Test demo wallet risks"""
        response = client.get("/demo/wallet-risks")
        assert response.status_code == 200
        data = response.json()
        assert "wallets" in data or "total_analyzed" in data
    
    def test_demo_threat_events(self, client):
        """Test demo threat events"""
        response = client.get("/demo/threat-events")
        assert response.status_code == 200
        data = response.json()
        assert "events" in data
        assert len(data["events"]) > 0
        assert "threat_level" in data["events"][0]

class TestAnalyticsEndpoints:
    """Test analytics endpoints"""
    
    def test_threat_distribution(self, client):
        """Test threat distribution analytics"""
        response = client.get("/analytics/threat-distribution")
        assert response.status_code == 200
        data = response.json()
        assert "critical" in data
        assert "high" in data
        assert "medium" in data
        assert "low" in data
    
    def test_entity_types(self, client):
        """Test entity types distribution"""
        response = client.get("/analytics/entity-types")
        assert response.status_code == 200
        data = response.json()
        assert "wallet_addresses" in data
        assert "emails" in data
        assert "domains" in data
    
    def test_wallet_risk_distribution(self, client):
        """Test wallet risk distribution"""
        response = client.get("/analytics/wallet-risk-distribution")
        assert response.status_code == 200
        data = response.json()
        assert "critical" in data
        assert "high" in data
        assert "clean" in data

class TestErrorHandling:
    """Test error handling"""
    
    def test_404_not_found(self, client):
        """Test 404 error"""
        response = client.get("/nonexistent/endpoint")
        assert response.status_code == 404
    
    def test_invalid_json(self, client):
        """Test invalid JSON in request"""
        response = client.post("/threats/analyze", 
                              data="invalid json",
                              headers={"Content-Type": "application/json"})
        assert response.status_code in [400, 422]
    
    def test_missing_required_field(self, client):
        """Test missing required field in request"""
        response = client.post("/threats/analyze", json={})
        assert response.status_code == 422

class TestPerformance:
    """Test API performance"""
    
    def test_demo_response_time(self, client):
        """Test that demo endpoints respond quickly"""
        import time
        start = time.time()
        response = client.get("/demo/dashboard")
        elapsed = time.time() - start
        
        assert response.status_code == 200
        assert elapsed < 1.0, "Demo response should be < 1 second"
    
    def test_concurrent_requests(self, client):
        """Test handling concurrent requests"""
        responses = []
        for _ in range(5):
            response = client.get("/health")
            responses.append(response)
        
        assert all(r.status_code == 200 for r in responses)

class TestDataIntegrity:
    """Test data integrity"""
    
    def test_dashboard_stats_consistency(self, client):
        """Test that dashboard stats are consistent"""
        response1 = client.get("/demo/dashboard")
        response2 = client.get("/demo/dashboard")
        
        assert response1.status_code == 200
        assert response2.status_code == 200
        
        # Both should have same structure
        data1 = response1.json()
        data2 = response2.json()
        assert data1["stats"]["critical_threats"] == data2["stats"]["critical_threats"]
    
    def test_threat_events_have_required_fields(self, client):
        """Test that threat events have all required fields"""
        response = client.get("/demo/threat-events")
        data = response.json()
        
        required_fields = ["id", "source", "threat_level", "message", "entities", "timestamp"]
        for event in data["events"]:
            for field in required_fields:
                assert field in event, f"Missing field: {field}"

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
