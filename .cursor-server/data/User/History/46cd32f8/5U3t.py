import subprocess
import pandas as pd
import joblib
import shap
from scapy.all import sniff, IP, TCP, UDP
import os

# 1. Load the Brain we created yesterday
model = joblib.load('ips_model.pkl')
explainer = shap.TreeExplainer(model)

def block_ip(ip_address):
    """Adds a firewall rule to drop all traffic from the malicious IP."""
    try:
        # Command: sudo iptables -A INPUT -s [IP] -j DROP
        # -A INPUT: Add to incoming traffic list
        # -s: source IP
        # -j DROP: Block it completely
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        print(f"✅ [FIREWALL] Successfully blocked IP: {ip_address}")
    except Exception as e:
        print(f"❌ Failed to block IP: {e}")

def explain_prediction(features_list):
    """Explain why the AI flagged this packet."""
    shap_values = explainer.shap_values(pd.DataFrame([features_list], 
                  columns=['Dst Port', 'Pkt Len Max', 'Flow Duration', 'Protocol']))
    
    # Get index of the most influential feature
    top_feature_idx = shap_values[1][0].argmax()
    feature_names = ['Dst Port', 'Pkt Len Max', 'Flow Duration', 'Protocol']
    return feature_names[top_feature_idx]

def packet_callback(packet):
    if IP in packet:
        # 1. Extract Features exactly as before
        dst_port = packet.dport if (TCP in packet or UDP in packet) else 0
        pkt_len = len(packet)
        protocol = packet.proto
        
        # 2. Create a small DataFrame with the correct column names
        # This fixes the "valid feature names" error!
        current_features = pd.DataFrame([[dst_port, pkt_len, 100, protocol]], 
                                       columns=['Dst Port', 'Pkt Len Max', 'Flow Duration', 'Protocol'])
        
        # 3. Predict using the DataFrame
        prediction = model.predict(current_features)[0]
        
        if prediction == 1:
            # 4. Explain using SHAP
            # We pass the same DataFrame to SHAP
            reason = explain_prediction(current_features)
            print(f"\n[!!!] ATTACK DETECTED from {packet[IP].src}")
            print(f"Reason: High contribution from '{reason}'")
            print(f"Action: Preparing to block IP...")

# 5. Start Sniffing (Requires sudo)
print("Starting Live X-IPS Sniffer... (Press Ctrl+C to stop)")
# Change this line at the bottom:
sniff(prn=packet_callback, filter="ip", store=0, iface=None)