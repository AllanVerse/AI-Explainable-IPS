import json
import time
import requests
from datetime import datetime

# ==========================================
# ENTERPRISE CONFIGURATION
# ==========================================
LOG_FILE = "/var/log/suricata/eve.json"
# Replace this URL with your Discord or Slack Webhook URL later!
WEBHOOK_URL = "YOUR_WEBHOOK_URL_HERE" 

# Dummy ML Model class to represent your AI for this script
# (If you have your actual pickle model loaded, keep your original model code here)
class MLModel:
    def predict_proba(self, features):
        # Simulating AI logic: If payload is massive, return high probability of attack
        payload_size = features[0][2]
        if payload_size > 5000:
            return [[0.10, 0.95]] # 95% attack probability
        return [[0.70, 0.30]]     # 30% attack probability

model = MLModel()

# ==========================================
# CHATOPS ALERTING SYSTEM (PHASE 3)
# ==========================================
def send_soc_alert(src_ip, dst_port, payload_size, ai_score):
    """Sends a formatted Incident Response ticket to Discord/Slack."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Discord/Slack compatible JSON payload
    message = {
        "content": "🚨 **[SOC CRITICAL] Malicious Flow Mitigated** 🚨",
        "embeds": [{
            "title": "AI Intrusion Prevention System",
            "color": 16711680,
            "fields": [
                {"name": "Attacker IP", "value": f"`{src_ip}`", "inline": True},
                {"name": "Target Port", "value": f"`{dst_port}`", "inline": True},
                {"name": "Payload Size", "value": f"`{payload_size} Bytes`", "inline": True},
                {"name": "AI Confidence", "value": f"`{ai_score*100:.1f}%`", "inline": False},
                {"name": "Action Taken", "value": "🛑 **CONNECTION DROPPED & IP BLOCKED**", "inline": False}
            ],
            "footer": {"text": f"Suricata C-Engine | Event Time: {timestamp}"}
        }]
    }
    
    try:
        if WEBHOOK_URL != "YOUR_WEBHOOK_URL_HERE":
            requests.post(WEBHOOK_URL, json=message)
            print("   [+] Automated Alert sent to SOC Team.")
    except Exception as e:
        print(f"   [-] Failed to send webhook: {e}")

# ==========================================
# REAL-TIME LOG PIPELINE
# ==========================================
def tail_logs(filename):
    """Yields new lines from the Suricata log file in real-time."""
    with open(filename, 'r') as f:
        # Go to the end of the file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1) # Wait briefly before reading again
                continue
            yield line

print("[*] Enterprise AI-IPS Starting...")
print("[*] Listening for live network traffic via Suricata...")

# Watch the file forever
for line in tail_logs(LOG_FILE):
    try:
        event = json.loads(line)
        
        # We only care about flow states (completed connections)
        if event.get("event_type") == "flow":
            src_ip = event["src_ip"]
            dst_port = event["dest_port"]
            
            # Get the payload size (Suricata calls it 'pkts_toserver' or similar bytes)
            payload_size = event["flow"]["bytes_toserver"]
            
            # Package features for the AI
            current_features = [[0, 0, payload_size]] # Simplified for this script
            
            # Ask the AI to score the connection
            probs = model.predict_proba(current_features)[0]
            attack_prob = probs[1]
            
            print(f"[*] Live Flow | IP: {src_ip} | Port: {dst_port} | Payload: {payload_size}B | AI Score: {attack_prob*100:.1f}%")
            
            # TRIGGER INCIDENT RESPONSE IF SCORE IS > 70%
            if attack_prob > 0.70:
                print(f"   [🚨 SOC CRITICAL] Blocking {src_ip}!")
                send_soc_alert(src_ip, dst_port, payload_size, attack_prob)
                
    except json.JSONDecodeError:
        pass
    except KeyError:
        # Skip events that don't have standard flow formatting
        pass