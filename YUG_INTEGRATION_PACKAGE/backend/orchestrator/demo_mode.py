"""
Demo Mode Handler - Cached Data Management
Switches between live API calls and pre-computed demo data
"""

import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)

class DemoDataType(Enum):
    """Types of demo data available"""
    CRAWLED_MESSAGES = "crawled_messages"
    THREAT_ANALYSIS = "threat_analysis"
    WALLET_RISKS = "wallet_risks"
    THREAT_EVENTS = "threat_events"

class DemoMode:
    """
    Manages demo/cached data for the platform
    Allows instant demos even without:
    - Tor connectivity
    - API keys
    - Live blockchain data
    """
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.demo_data = self._load_demo_data()
        logger.info(f"Demo mode: {'ENABLED' if enabled else 'DISABLED'}")
    
    def _load_demo_data(self) -> Dict[str, Any]:
        """Load all demo data"""
        return {
            "crawled_messages": self.get_demo_crawled_data(),
            "threat_analysis": self.get_demo_threat_analysis(),
            "wallet_risks": self.get_demo_wallet_risks(),
            "threat_events": self.get_demo_threat_events()
        }
    
    def get_demo_crawled_data(self) -> List[Dict]:
        """Get pre-scraped .onion site data"""
        return [
            {
                "url": "http://marketplace.onion",
                "timestamp": "2024-04-03T10:30:00",
                "title": "Dark Market",
                "content": "User selling stolen credentials and database dumps. Offering access to compromised corporate networks.",
                "threat_indicators": ["data_breach", "credential_theft", "ransomware"]
            },
            {
                "url": "http://forum.onion",
                "timestamp": "2024-04-03T09:15:00",
                "title": "Hacker Forum",
                "content": "Discussion about latest vulnerability in payment systems. Code provided for exploitation.",
                "threat_indicators": ["exploit_code", "vulnerability_discussion"]
            },
            {
                "url": "http://exchange.onion",
                "timestamp": "2024-04-03T08:45:00",
                "title": "Crypto Exchange",
                "content": "Cryptocurrency mixed with AML circumvention techniques discussed.",
                "threat_indicators": ["money_laundering", "mixer_service"]
            },
            {
                "url": "http://leaked.onion",
                "timestamp": "2024-04-03T07:20:00",
                "title": "Leak Database",
                "content": "Database of 50,000 compromised email accounts from major tech company. Wallet addresses of threat actors included.",
                "threat_indicators": ["data_breach", "leaked_credentials"]
            },
            {
                "url": "http://malware.onion",
                "timestamp": "2024-04-03T06:00:00",
                "title": "Malware Repository",
                "content": "Selling ransomware variants and botnet access. Samples available for testing.",
                "threat_indicators": ["malware", "ransomware", "botnet"]
            }
        ]
    
    def get_demo_threat_analysis(self) -> Dict:
        """Get pre-analyzed threat data"""
        return {
            "total_analyzed": 50,
            "critical_threats": 5,
            "high_threats": 12,
            "medium_threats": 20,
            "threats": [
                {
                    "id": "threat_001",
                    "content": "Database leak containing 100k credentials from Fortune 500 company",
                    "threat_level": "critical",
                    "threat_score": 0.95,
                    "entities": [
                        {
                            "type": "wallet_address",
                            "value": "0x1a2b3c4d5e6f7g8h9i0j",
                            "confidence": 0.92
                        },
                        {
                            "type": "email",
                            "value": "attacker@protonmail.com",
                            "confidence": 0.88
                        }
                    ]
                },
                {
                    "id": "threat_002",
                    "content": "Ransomware-as-a-Service operation with 15 victims this month",
                    "threat_level": "critical",
                    "threat_score": 0.93,
                    "entities": [
                        {
                            "type": "wallet_address",
                            "value": "0x9z8y7x6w5v4u3t2s1r0q",
                            "confidence": 0.95
                        }
                    ]
                },
                {
                    "id": "threat_003",
                    "content": "Zero-day exploit code released for popular web framework",
                    "threat_level": "high",
                    "threat_score": 0.85,
                    "entities": []
                },
                {
                    "id": "threat_004",
                    "content": "Credential stuffing attack against fintech platforms",
                    "threat_level": "high",
                    "threat_score": 0.78,
                    "entities": [
                        {
                            "type": "email",
                            "value": "credentials123@temp.org",
                            "confidence": 0.81
                        }
                    ]
                },
                {
                    "id": "threat_005",
                    "content": "DDoS-for-hire service marketing",
                    "threat_level": "medium",
                    "threat_score": 0.65,
                    "entities": []
                }
            ]
        }
    
    def get_demo_wallet_risks(self) -> Dict:
        """Get pre-analyzed wallet risk data"""
        return {
            "total_analyzed": 30,
            "high_risk": 8,
            "medium_risk": 15,
            "wallets": [
                {
                    "address": "0x1a2b3c4d5e6f7g8h9i0j",
                    "risk_level": "critical",
                    "score": 0.98,
                    "balance": 125.45,
                    "transactions": 892,
                    "factors": ["mixer_detected", "high_velocity", "linked_to_ransomware"]
                },
                {
                    "address": "0x9z8y7x6w5v4u3t2s1r0q",
                    "risk_level": "high",
                    "score": 0.87,
                    "balance": 87.30,
                    "transactions": 634,
                    "factors": ["suspicious_pattern", "linked_to_theft", "frequent_cashout"]
                },
                {
                    "address": "0x5a5b5c5d5e5f5a5b5c5d",
                    "risk_level": "high",
                    "score": 0.82,
                    "balance": 203.15,
                    "transactions": 512,
                    "factors": ["high_volume", "mixing_activity", "dark_exchange_link"]
                },
                {
                    "address": "0x1q1w1e1r1t1y1u1i1o1p",
                    "risk_level": "medium",
                    "score": 0.65,
                    "balance": 45.60,
                    "transactions": 245,
                    "factors": ["moderate_volume", "some_mixing", "unknown_source"]
                },
                {
                    "address": "0x2q2w2e2r2t2y2u2i2o2p",
                    "risk_level": "low",
                    "score": 0.35,
                    "balance": 12.30,
                    "transactions": 45,
                    "factors": ["low_volume"]
                }
            ]
        }
    
    def get_demo_threat_events(self) -> List[Dict]:
        """Get complete threat events (crawl + analysis + blockchain)"""
        return [
            {
                "id": "event_001",
                "source": "http://marketplace.onion",
                "threat_level": "critical",
                "threat_score": 0.95,
                "message": "Database leak: 100k employee records from TechCorp. Wallet address provided for ransom payment.",
                "entities": [
                    {
                        "type": "wallet_address",
                        "value": "0x1a2b3c4d5e6f7g8h9i0j",
                        "risk_score": 0.98,
                        "risk_level": "critical"
                    },
                    {
                        "type": "email",
                        "value": "ransom@tempmail.com",
                        "confidence": 0.85
                    }
                ],
                "tags": ["data_breach", "extortion", "critical"],
                "timestamp": "2024-04-03T10:30:00"
            },
            {
                "id": "event_002",
                "source": "http://forum.onion",
                "threat_level": "critical",
                "threat_score": 0.93,
                "message": "RaaS operation advertising 15 victims compromised this month. Accepting Bitcoin payments.",
                "entities": [
                    {
                        "type": "wallet_address",
                        "value": "0x9z8y7x6w5v4u3t2s1r0q",
                        "risk_score": 0.87,
                        "risk_level": "high"
                    }
                ],
                "tags": ["ransomware", "extortion", "operations"],
                "timestamp": "2024-04-03T09:45:00"
            },
            {
                "id": "event_003",
                "source": "http://exploit.onion",
                "threat_level": "high",
                "threat_score": 0.85,
                "message": "Zero-day exploit code released for CVE-2024-1234. Weaponized version available.",
                "entities": [],
                "tags": ["exploit", "zero_day", "code_release"],
                "timestamp": "2024-04-03T08:20:00"
            },
            {
                "id": "event_004",
                "source": "http://leaked.onion",
                "threat_level": "high",
                "threat_score": 0.82,
                "message": "50000 credentials leaked from PaymentGateway. Live testing tools provided.",
                "entities": [
                    {
                        "type": "email",
                        "value": "stolen_credentials@temp.org",
                        "confidence": 0.88
                    }
                ],
                "tags": ["credential_theft", "data_breach", "financial"],
                "timestamp": "2024-04-03T07:15:00"
            },
            {
                "id": "event_005",
                "source": "http://malware.onion",
                "threat_level": "high",
                "threat_score": 0.78,
                "message": "Botnet samples available for purchase. C2 infrastructure currently active.",
                "entities": [],
                "tags": ["malware", "botnet", "command_and_control"],
                "timestamp": "2024-04-03T06:30:00"
            }
        ]
    
    def get_data(self, data_type: DemoDataType) -> Any:
        """
        Get demo data by type
        
        Args:
            data_type: Type of demo data to retrieve
            
        Returns:
            Demo data or empty structure if demo mode disabled
        """
        if not self.enabled:
            return None
        
        mapping = {
            DemoDataType.CRAWLED_MESSAGES: self.get_demo_crawled_data,
            DemoDataType.THREAT_ANALYSIS: lambda: self.get_demo_threat_analysis(),
            DemoDataType.WALLET_RISKS: lambda: self.get_demo_wallet_risks(),
            DemoDataType.THREAT_EVENTS: self.get_demo_threat_events,
        }
        
        getter = mapping.get(data_type)
        if getter:
            return getter()
        
        return None
    
    def get_dashboard_demo_data(self) -> Dict:
        """Get complete demo data for dashboard"""
        threats = self.get_demo_threat_analysis()
        wallets = self.get_demo_wallet_risks()
        events = self.get_demo_threat_events()
        
        return {
            "stats": {
                "total_threats_analyzed": threats.get("total_analyzed", 0),
                "critical_threats": threats.get("critical_threats", 0),
                "suspicious_wallets_found": wallets.get("high_risk", 0),
                "total_volume_tracked": sum(w["balance"] for w in wallets.get("wallets", [])),
                "last_crawl_time": datetime.now().isoformat(),
                "crawler_status": "demo_mode"
            },
            "recent_threats": events[:5],
            "top_wallets": wallets.get("wallets", [])[:5],
            "threat_summary": {
                "critical": threats.get("critical_threats", 0),
                "high": threats.get("high_threats", 0),
                "medium": threats.get("medium_threats", 0)
            },
            "timestamp": datetime.now().isoformat()
        }
    
    def toggle(self, enabled: bool):
        """Toggle demo mode on/off"""
        self.enabled = enabled
        logger.info(f"Demo mode toggled: {'ON' if enabled else 'OFF'}")

# Global demo mode instance
_demo_mode_instance: Optional[DemoMode] = None

def get_demo_mode(enabled: bool = True) -> DemoMode:
    """Get or create demo mode instance"""
    global _demo_mode_instance
    if _demo_mode_instance is None:
        _demo_mode_instance = DemoMode(enabled=enabled)
    return _demo_mode_instance
