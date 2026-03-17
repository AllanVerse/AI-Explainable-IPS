import json
import os
from datetime import datetime, timedelta

def seed_intelligence():
    # Example malicious IPs found in recent threat feeds
    malicious_ips = {
        "185.156.177.10": [{"time": str(datetime.now() - timedelta(minutes=10)), "reason": "Known Botnet"}],
        "45.33.32.156": [{"time": str(datetime.now() - timedelta(hours=1)), "reason": "Port Scan Pattern"}]
    }

    # Common attack patterns to recognize
    patterns = {
        "Brute Force": {"threshold": 3, "time_window_sec": 60, "action": "BLOCK_PERMANENT"},
        "DDoS": {"threshold": 50, "time_window_sec": 10, "action": "BLOCK_PERMANENT"},
        "Suspicious Probe": {"threshold": 1, "time_window_sec": 0, "action": "DECEPTION_REDIRECT"}
    }

    db = {
        "malicious_ips": malicious_ips,
        "patterns": patterns,
        "hitl_logs": [] # For Human-in-the-Loop review
    }

    with open('threat_db.json', 'w') as f:
        json.dump(db, f, indent=4)
    
    print("✅ Success: 'threat_db.json' created with historical attack patterns.")

if __name__ == "__main__":
    seed_intelligence()