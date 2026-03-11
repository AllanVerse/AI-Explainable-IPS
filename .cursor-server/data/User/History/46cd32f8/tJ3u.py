import subprocess
import pandas as pd
import joblib
import shap
from scapy.all import sniff, IP, TCP, UDP
import os
import os

# This finds the folder where live_ips.py is located
base_path = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_path, 'ips_model.pkl')

# Now load using the full path
model = joblib.load(model_path)
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

def explain_prediction(features_df):
    """Explain why the AI flagged this packet."""
    # .values[0] ensures we pass the raw data row to SHAP
    shap_values = explainer.shap_values(features_df)
    
    # SHAP for Random Forest often returns a list [Base, Attack]
    # We take the values for the 'Attack' class (index 1)
    if isinstance(shap_values, list):
        val = shap_values[1][0]
    else:
        val = shap_values[0]
        
    # Find which feature had the highest impact
    top_feature_idx = val.argmax()
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
sniff(prn=packet_callback, filter="ip", store=0, iface="lo")