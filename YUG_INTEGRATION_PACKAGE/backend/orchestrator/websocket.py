"""
WebSocket Handlers for Real-time Updates
Provides live streaming of threat analysis and crawler status
"""

from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, List, Set
import asyncio
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class ConnectionManager:
    """Manages WebSocket client connections"""
    
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, channel: str):
        """Accept and register a WebSocket connection"""
        await websocket.accept()
        
        if channel not in self.active_connections:
            self.active_connections[channel] = []
        
        self.active_connections[channel].append(websocket)
        logger.info(f"Client connected to channel: {channel}")
    
    def disconnect(self, websocket: WebSocket, channel: str):
        """Remove a disconnected client"""
        if channel in self.active_connections:
            self.active_connections[channel].remove(websocket)
            if len(self.active_connections[channel]) == 0:
                del self.active_connections[channel]
        logger.info(f"Client disconnected from channel: {channel}")
    
    async def broadcast(self, channel: str, message: dict):
        """Broadcast message to all clients in a channel"""
        if channel not in self.active_connections:
            return
        
        # Add timestamp
        message["timestamp"] = datetime.now().isoformat()
        message_json = json.dumps(message)
        
        # Send to all clients, remove dead connections
        dead_connections = []
        for connection in self.active_connections[channel]:
            try:
                await connection.send_text(message_json)
            except Exception as e:
                logger.error(f"Error sending message: {e}")
                dead_connections.append(connection)
        
        # Clean up dead connections
        for connection in dead_connections:
            self.disconnect(connection, channel)
    
    async def broadcast_to_all(self, message: dict):
        """Broadcast message to all channels"""
        for channel in self.active_connections:
            await self.broadcast(channel, message)

# Global connection manager
manager = ConnectionManager()

class CrawlerStreamHandler:
    """Handle crawler status streaming"""
    
    @staticmethod
    async def stream_crawler_status(websocket: WebSocket):
        """Stream crawler progress updates"""
        channel = "crawler"
        await manager.connect(websocket, channel)
        
        try:
            while True:
                # Receive commands from client (e.g., stop crawling)
                data = await websocket.receive_text()
                command = json.loads(data)
                
                if command.get("action") == "ping":
                    # Echo pong for keep-alive
                    await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
        
        except WebSocketDisconnect:
            manager.disconnect(websocket, channel)
        except Exception as e:
            logger.error(f"Crawler stream error: {e}")
            manager.disconnect(websocket, channel)

class ThreatStreamHandler:
    """Handle threat analysis streaming"""
    
    @staticmethod
    async def stream_threat_updates(websocket: WebSocket):
        """Stream threat analysis results"""
        channel = "threats"
        await manager.connect(websocket, channel)
        
        try:
            while True:
                data = await websocket.receive_text()
                command = json.loads(data)
                
                # Handle different commands
                if command.get("action") == "get-threats":
                    # Send current threats
                    threats = {
                        "type": "threats",
                        "threats": get_mock_threats(),
                        "count": len(get_mock_threats())
                    }
                    await websocket.send_json(threats)
                
                elif command.get("action") == "filter":
                    # Send filtered threats
                    threat_level = command.get("level", "all")
                    threats = {
                        "type": "filtered-threats",
                        "level": threat_level,
                        "threats": get_mock_threats()  # Would filter in real implementation
                    }
                    await websocket.send_json(threats)
                
                elif command.get("action") == "ping":
                    await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
        
        except WebSocketDisconnect:
            manager.disconnect(websocket, channel)
        except Exception as e:
            logger.error(f"Threat stream error: {e}")
            manager.disconnect(websocket, channel)

class DashboardStreamHandler:
    """Handle dashboard real-time updates"""
    
    @staticmethod
    async def stream_dashboard_updates(websocket: WebSocket):
        """Stream dashboard statistics updates"""
        channel = "dashboard"
        await manager.connect(websocket, channel)
        
        try:
            while True:
                data = await websocket.receive_text()
                command = json.loads(data)
                
                if command.get("action") == "ping":
                    await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
                
                elif command.get("action") == "get-stats":
                    # Send current dashboard stats
                    stats = {
                        "type": "stats",
                        "total_threats": 150,
                        "critical_threats": 5,
                        "suspicious_wallets": 8,
                        "total_volume": 1250.50,
                        "last_update": datetime.now().isoformat()
                    }
                    await websocket.send_json(stats)
        
        except WebSocketDisconnect:
            manager.disconnect(websocket, channel)
        except Exception as e:
            logger.error(f"Dashboard stream error: {e}")
            manager.disconnect(websocket, channel)

class ConsoleStreamHandler:
    """Handle live console/terminal streaming"""
    
    @staticmethod
    async def stream_console_output(websocket: WebSocket):
        """Stream live console/terminal output"""
        channel = "console"
        await manager.connect(websocket, channel)
        
        try:
            # Send initial message
            await websocket.send_json({
                "type": "console-ready",
                "message": "DarkIntel-AI Console Ready",
                "timestamp": datetime.now().isoformat()
            })
            
            while True:
                data = await websocket.receive_text()
                command = json.loads(data)
                
                if command.get("action") == "execute":
                    # Simulate command execution
                    cmd = command.get("command", "")
                    result = simulate_command_execution(cmd)
                    
                    await websocket.send_json({
                        "type": "console-output",
                        "command": cmd,
                        "output": result,
                        "timestamp": datetime.now().isoformat()
                    })
                
                elif command.get("action") == "ping":
                    await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
        
        except WebSocketDisconnect:
            manager.disconnect(websocket, channel)
        except Exception as e:
            logger.error(f"Console stream error: {e}")
            manager.disconnect(websocket, channel)

# ============================================
# Mock Data Functions
# ============================================

def get_mock_threats():
    """Get mock threat data"""
    return [
        {
            "id": "threat_001",
            "level": "critical",
            "message": "Database leak detected",
            "timestamp": datetime.now().isoformat()
        },
        {
            "id": "threat_002",
            "level": "high",
            "message": "Ransomware infrastructure active",
            "timestamp": datetime.now().isoformat()
        }
    ]

def simulate_command_execution(command: str) -> str:
    """Simulate command execution"""
    commands = {
        "info": "DarkIntel-AI v1.0.0 | Threat Intelligence Platform",
        "status": "✓ Crawler running | ✓ NLP module ready | ✓ Blockchain connected",
        "threats": "Found 12 critical threats | 35 high threats | 54 medium threats",
        "wallets": "Analyzing 30 wallets | Found 8 high-risk addresses",
        "help": "Commands: info, status, threats, wallets, clear",
        "clear": ""
    }
    
    return commands.get(command, f"Command not found: {command}")

# ============================================
# Broadcast Functions
# ============================================

async def broadcast_threat_update(threat_data: dict):
    """Broadcast threat update to all connected clients"""
    message = {
        "type": "threat-update",
        "data": threat_data
    }
    await manager.broadcast("threats", message)
    await manager.broadcast("dashboard", message)

async def broadcast_crawler_progress(progress: dict):
    """Broadcast crawler progress"""
    message = {
        "type": "crawler-progress",
        "data": progress
    }
    await manager.broadcast("crawler", message)

async def broadcast_console_message(message: str, level: str = "info"):
    """Broadcast console message"""
    message_obj = {
        "type": "console-message",
        "level": level,
        "message": message
    }
    await manager.broadcast("console", message_obj)
