import pandas as pd
import joblib
from scapy.all import sniff, IP, TCP, UDP
from threat_intel import ThreatEngine
from mitigator import apply_defense
import os

# 1. Initialize our new modules
engine = ThreatEngine()
model = joblib.load('/home/aln/ai_ips_project/ips_model.pkl')

def explain_prediction(features_df):
    """Simple feature impact tracker for the demo"""
    # In a real demo, this would use your SHAP logic
    feature_names = ['Dst Port', 'Pkt Len Max', 'Flow Duration', 'Protocol']
    # Return the feature with the highest value as the 'reason'
    return feature_names[features_df.values.argmax()]

def packet_callback(packet):
    if IP in packet:
        attacker_ip = packet[IP].src
        dst_port = packet.dport if (TCP in packet or UDP in packet) else 0
        pkt_len = len(packet)
        protocol = packet.proto
        
        # Prepare data for AI
        current_features = pd.DataFrame([[dst_port, pkt_len, 100, protocol]], 
                                       columns=['Dst Port', 'Pkt Len Max', 'Flow Duration', 'Protocol'])
        
        # 2. S-GRADE ADDITION: Confidence Scoring
        # We use predict_proba to see HOW sure the AI is
        probs = model.predict_proba(current_features)[0]
        attack_prob = probs[1] 

        if attack_prob > 0.4: # Threshold for 'Suspicious'
            reason = explain_prediction(current_features)
            
            # 3. INNOVATION: Decision Logic (HITL / Pattern Matching)
            # This calls the threat_intel.py module we created
            action = engine.evaluate_threat(attacker_ip, attack_prob, reason)
            
            print(f"\n[!!!] AI ALERT | Target: {attacker_ip} | Prob: {attack_prob:.2f}")
            
            # 4. DECEPTION & DEFENSE: Apply the specific mitigation
            apply_defense(attacker_ip, action)
        else:
            # Silent monitor for normal traffic
            print(f"[*] Monitoring: {attacker_ip} -> Score: {attack_prob:.2f}", end='\r')

# Start the Sniffer
print("🚀 X-IPS Framework Version 2.0 Starting...")
print("Modules Loaded: [AI-Brain, Threat-Intel, Deception-Mitigator, HITL-Gate]")
sniff(prn=packet_callback, filter="ip", store=0, iface="lo")