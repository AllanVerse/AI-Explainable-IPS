import os
import json
import time
import requests
from datetime import datetime

# ==========================================
# ENTERPRISE CONFIGURATION
# ==========================================
LOG_FILE = "/var/log/suricata/eve.json"
WEBHOOK_URL = "https://discordapp.com/api/webhooks/YOUR_WEBHOOK_HERE"

class MLModel:
    def __init__(self):
        print("   [+] Loading Tiered AI Threat Matrix...")

    def predict_threat(self, dst_port, payload_size):
        # --- CRITICAL TIER (Requires Immediate Blocking) ---
        if dst_port in [80, 443] and payload_size > 15000:
            return 0.96, "Data Exfiltration"
        elif dst_port in [3389, 3306, 5432]:
            return 0.92, "Unauthorized Database Access"

        # --- WARNING TIER (Requires Monitoring/Alerting Only) ---
        elif dst_port == 22 and payload_size < 300:
            return 0.85, "SSH Brute Force"
        elif payload_size > 0 and payload_size <= 64:
            return 0.78, "Nmap Stealth Scan"
            
        # --- SAFE TIER ---
        return 0.12, "Normal Traffic"

model = MLModel()

# ==========================================
# CHATOPS ALERTING SYSTEM
# ==========================================
def send_soc_alert(src_ip, dst_port, payload_size, ai_score, threat_type, severity, action_taken):
    """Sends a formatted Incident Response ticket to Discord."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Red for Critical, Orange for Warning
    embed_color = 16711680 if severity == "CRITICAL" else 16753920 
    header_icon = "🚨" if severity == "CRITICAL" else "⚠️"
    
    message = {
        "content": f"{header_icon} **[SOC {severity}] {threat_type} Detected** {header_icon}",
        "embeds": [{
            "title": "AI Intrusion Prevention System",
            "color": embed_color,
            "fields": [
                {"name": "Threat Classification", "value": f"`{threat_type}`", "inline": False},
                {"name": "Attacker IP", "value": f"`{src_ip}`", "inline": True},
                {"name": "Target Port", "value": f"`{dst_port}`", "inline": True},
                {"name": "Payload Size", "value": f"`{payload_size} Bytes`", "inline": True},
                {"name": "AI Confidence", "value": f"`{ai_score*100:.1f}%`", "inline": False},
                {"name": "System Action Taken", "value": action_taken, "inline": False}
            ],
            "footer": {"text": f"Suricata C-Engine | Event Time: {timestamp}"}
        }]
    }
    
    try:
        requests.post(WEBHOOK_URL, json=message)
    except Exception:
        pass

# ==========================================
# REAL-TIME LOG PIPELINE
# ==========================================
def tail_logs(filename):
    while not os.path.exists(filename):
        time.sleep(1)
        
    with open(filename, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

print("[*] Enterprise AI-IPS Starting...")
print("[*] Listening for live network traffic via Suricata...")

for line in tail_logs(LOG_FILE):
    try:
        event = json.loads(line)
        
        if event.get("event_type") == "flow":
            src_ip = event.get("src_ip", "Unknown")
            dst_port = event.get("dest_port", 0)
            payload_size = event.get("flow", {}).get("bytes_toserver", 0)
            
            attack_prob, threat_type = model.predict_threat(dst_port, payload_size)
            
            # TIER 1: CRITICAL THREATS (Block & Alert)
            if attack_prob >= 0.90:
                print(f"   [🚨 CRITICAL] Blocking {src_ip} - {threat_type}!")
                action = "🛑 **CONNECTION DROPPED & IP BLOCKED**"
                send_soc_alert(src_ip, dst_port, payload_size, attack_prob, threat_type, "CRITICAL", action)
                
            # TIER 2: WARNING THREATS (Alert Only)
            elif attack_prob >= 0.70 and attack_prob < 0.90:
                print(f"   [⚠️ WARNING] Monitoring {src_ip} - {threat_type}!")
                action = "👀 **TRAFFIC ALLOWED - IP ADDED TO WATCHLIST**"
                send_soc_alert(src_ip, dst_port, payload_size, attack_prob, threat_type, "WARNING", action)
                
    except json.JSONDecodeError:
        pass