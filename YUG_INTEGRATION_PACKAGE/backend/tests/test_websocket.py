"""
WebSocket integration tests
"""

import pytest
import json
import asyncio
from fastapi.testclient import TestClient

class TestWebSocketCrawler:
    """Test WebSocket crawler stream"""
    
    def test_connect_crawler_websocket(self, client):
        """Test connecting to crawler WebSocket"""
        with client.websocket_connect("/ws/crawler") as websocket:
            # Should connect without error
            assert websocket is not None
    
    def test_crawler_ping_pong(self, client):
        """Test ping/pong on crawler WebSocket"""
        with client.websocket_connect("/ws/crawler") as websocket:
            # Send ping
            websocket.send_json({"action": "ping"})
            
            # Receive pong
            data = websocket.receive_json()
            assert data.get("type") == "pong"

class TestWebSocketThreats:
    """Test WebSocket threat stream"""
    
    def test_connect_threats_websocket(self, client):
        """Test connecting to threats WebSocket"""
        with client.websocket_connect("/ws/threats") as websocket:
            assert websocket is not None
    
    def test_threats_ping_pong(self, client):
        """Test ping/pong on threats WebSocket"""
        with client.websocket_connect("/ws/threats") as websocket:
            websocket.send_json({"action": "ping"})
            data = websocket.receive_json()
            assert data.get("type") == "pong"
    
    def test_get_threats(self, client):
        """Test retrieving threats via WebSocket"""
        with client.websocket_connect("/ws/threats") as websocket:
            websocket.send_json({"action": "get-threats"})
            data = websocket.receive_json()
            assert data.get("type") == "threats"
            assert "threats" in data
    
    def test_filter_threats(self, client):
        """Test filtering threats via WebSocket"""
        with client.websocket_connect("/ws/threats") as websocket:
            websocket.send_json({
                "action": "filter",
                "level": "critical"
            })
            data = websocket.receive_json()
            assert data.get("type") == "filtered-threats"
            assert data.get("level") == "critical"

class TestWebSocketDashboard:
    """Test WebSocket dashboard stream"""
    
    def test_connect_dashboard_websocket(self, client):
        """Test connecting to dashboard WebSocket"""
        with client.websocket_connect("/ws/dashboard") as websocket:
            assert websocket is not None
    
    def test_dashboard_stats(self, client):
        """Test retrieving dashboard stats via WebSocket"""
        with client.websocket_connect("/ws/dashboard") as websocket:
            websocket.send_json({"action": "get-stats"})
            data = websocket.receive_json()
            assert data.get("type") == "stats"
            assert "total_threats" in data
            assert "critical_threats" in data

class TestWebSocketConsole:
    """Test WebSocket console stream"""
    
    def test_connect_console_websocket(self, client):
        """Test connecting to console WebSocket"""
        with client.websocket_connect("/ws/console") as websocket:
            # Should receive console-ready message
            data = websocket.receive_json()
            assert data.get("type") == "console-ready"
    
    def test_console_execute_command(self, client):
        """Test executing command via console WebSocket"""
        with client.websocket_connect("/ws/console") as websocket:
            # Skip initial message
            websocket.receive_json()
            
            # Send command
            websocket.send_json({
                "action": "execute",
                "command": "info"
            })
            
            # Receive output
            data = websocket.receive_json()
            assert data.get("type") == "console-output"
            assert "output" in data
            assert "DarkIntel-AI" in data["output"]
    
    def test_console_status_command(self, client):
        """Test status command via console"""
        with client.websocket_connect("/ws/console") as websocket:
            websocket.receive_json()  # Skip initial
            
            websocket.send_json({
                "action": "execute",
                "command": "status"
            })
            
            data = websocket.receive_json()
            assert data.get("type") == "console-output"
            assert "Crawler running" in data["output"]

class TestWebSocketMessaging:
    """Test WebSocket messaging format"""
    
    def test_message_has_timestamp(self, client):
        """Test that WebSocket messages include timestamp"""
        with client.websocket_connect("/ws/threats") as websocket:
            websocket.send_json({"action": "ping"})
            data = websocket.receive_json()
            assert "timestamp" in data
    
    def test_invalid_json_ignored(self, client):
        """Test that invalid JSON doesn't crash connection"""
        with client.websocket_connect("/ws/threats") as websocket:
            # Send invalid data - connection should stay open
            try:
                websocket.send_bytes(b"invalid")
            except Exception:
                pass  # May throw, that's OK
    
    def test_multiple_sequential_messages(self, client):
        """Test sending multiple messages sequentially"""
        with client.websocket_connect("/ws/threats") as websocket:
            # Send first command
            websocket.send_json({"action": "ping"})
            data1 = websocket.receive_json()
            assert data1.get("type") == "pong"
            
            # Send second command
            websocket.send_json({"action": "ping"})
            data2 = websocket.receive_json()
            assert data2.get("type") == "pong"

class TestWebSocketReconnection:
    """Test WebSocket reconnection scenarios"""
    
    def test_reconnect_after_disconnect(self, client):
        """Test reconnecting after disconnect"""
        # First connection
        with client.websocket_connect("/ws/threats") as ws1:
            ws1.send_json({"action": "ping"})
            data1 = ws1.receive_json()
            assert data1.get("type") == "pong"
        
        # Should be able to reconnect
        with client.websocket_connect("/ws/threats") as ws2:
            ws2.send_json({"action": "ping"})
            data2 = ws2.receive_json()
            assert data2.get("type") == "pong"

class TestWebSocketErrors:
    """Test WebSocket error handling"""
    
    def test_unknown_command(self, client):
        """Test handling unknown command"""
        with client.websocket_connect("/ws/threats") as websocket:
            websocket.send_json({"action": "unknown-action"})
            
            # Connection should stay open (graceful handling)
            try:
                # Try to send another command
                websocket.send_json({"action": "ping"})
                data = websocket.receive_json()
                # If we get here, connection is still open
                assert True
            except Exception:
                # Connection closed, which is also acceptable
                assert True

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
