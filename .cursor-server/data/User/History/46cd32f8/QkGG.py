import pandas as pd
import joblib
import shap
from scapy.all import sniff, IP, TCP, UDP
import os

# 1. Load the Brain we created yesterday
model = joblib.load('ips_model.pkl')
explainer = shap.TreeExplainer(model)

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
        # 2. Extract Features (matching our training)
        dst_port = packet.dport if (TCP in packet or UDP in packet) else 0
        pkt_len = len(packet)
        protocol = packet.proto
        
        # Simplified 'duration' for real-time demo
        features = [dst_port, pkt_len, 100, protocol] 
        
        # 3. Predict
        prediction = model.predict([features])[0]
        
        if prediction == 1:
            # 4. Explain using SHAP
            reason = explain_prediction(features)
            print(f"\n[!!!] ATTACK DETECTED from {packet[IP].src}")
            print(f"Reason: High contribution from '{reason}'")
            print(f"Action: Preparing to block IP...")

# 5. Start Sniffing (Requires sudo)
print("Starting Live X-IPS Sniffer... (Press Ctrl+C to stop)")
sniff(prn=packet_callback, filter="ip", store=0)