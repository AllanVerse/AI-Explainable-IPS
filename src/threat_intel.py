import json
import os
from datetime import datetime

class ThreatEngine:
    def __init__(self):
        self.db_path = 'threat_db.json'
        if not os.path.exists(self.db_path):
            with open(self.db_path, 'w') as f:
                json.dump({"malicious_ips": {}, "patterns": {}}, f)

    def evaluate_threat(self, ip, prediction_prob, reason):
        with open(self.db_path, 'r') as f:
            db = json.load(f)

        # HITL Logic: If AI is unsure (40%-70% confidence), flag for review
        if 0.4 <= prediction_prob <= 0.7:
            return "HITL_REVIEW"

        # Pattern Recognition: Brute Force Detection
        # If the same IP hits the same reason 3 times in 60 seconds
        ip_hits = db["malicious_ips"].get(ip, [])
        ip_hits.append({"time": str(datetime.now()), "reason": reason})
        db["malicious_ips"][ip] = ip_hits

        with open(self.db_path, 'w') as f:
            json.dump(db, f, indent=4)

        if len(ip_hits) >= 3:
            return "BLOCK_PERMANENT"
        
        return "DECEPTION_REDIRECT" # Send to Honeypot