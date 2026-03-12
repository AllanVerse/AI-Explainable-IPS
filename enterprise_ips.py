import json
import subprocess
import time
import joblib
import pandas as pd
import os

MODEL_PATH = '/home/aln/ai_ips_project/ips_model.pkl'
LOG_FILE = '/var/log/suricata/eve.json'

print(f"[*] Loading AI Model from {MODEL_PATH}...")
try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    print(f"[!] Error loading model: {e}")
    exit(1)

def follow_suricata_logs(file_path):
    print("🚀 [MNC-GRADE IPS] AI Bridge Connected to Suricata.")
    print("Listening for live enterprise traffic logs...\n")
    
    process = subprocess.Popen(['sudo', 'tail', '-F', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    while True:
        line = process.stdout.readline()
        if not line:
            time.sleep(0.01)
            continue
            
        try:
            event = json.loads(line.decode('utf-8'))
            if event.get('event_type') == 'flow':
                analyze_event(event)
        except json.JSONDecodeError:
            continue

def analyze_event(event):
    try:
        src_ip = event.get('src_ip')
        dst_port = event.get('dest_port', 0)
        proto_name = event.get('proto', 'UNKNOWN')
        
        protocol = 6 if proto_name == 'TCP' else 17 if proto_name == 'UDP' else 0
        
        flow_data = event.get('flow', {})
        pkts = flow_data.get('pkts_toserver', 1)
        bytes_to_server = flow_data.get('bytes_toserver', 0)
        pkt_len_max = int(bytes_to_server / pkts) if pkts > 0 else 0
        age = flow_data.get('age', 1) 
        
        current_features = pd.DataFrame([[dst_port, pkt_len_max, age, protocol]], 
                                       columns=['Dst Port', 'Pkt Len Max', 'Flow Duration', 'Protocol'])
        
        probs = model.predict_proba(current_features)[0]
        attack_prob = probs[1]

        # DEBUG VISIBILITY: Print exactly what the AI sees for every single connection
        print(f"[*] Live Flow | IP: {src_ip} | Port: {dst_port} | Payload: {pkt_len_max}B | AI Score: {attack_prob*100:.1f}%")

        if attack_prob > 0.70:
            print(f"   [🚨 SOC CRITICAL] Blocking {src_ip}!")

    except Exception as e:
        pass

if __name__ == "__main__":
    follow_suricata_logs(LOG_FILE)