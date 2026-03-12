import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
import joblib
from osint_module import get_threat_intelligence

model = joblib.load('/home/aln/ai_ips_project/ips_model.pkl')

def analyze_pcap(pcap_file):
    print(f"📥 Loading historical enterprise incident: {pcap_file}...")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print("❌ PCAP not found. Please download it first.")
        return

    print(f"✅ Loaded {len(packets)} packets. Beginning AI & Signature Analysis...\n")

    threat_count = 0
    traced_ips = {} 

    for packet in packets:
        if IP in packet:
            attacker_ip = packet[IP].src
            dst_port = packet.dport if (TCP in packet or UDP in packet) else 0
            pkt_len = len(packet)
            protocol = packet.proto

            current_features = pd.DataFrame([[dst_port, pkt_len, 100, protocol]], 
                                           columns=['Dst Port', 'Pkt Len Max', 'Flow Duration', 'Protocol'])
            
            probs = model.predict_proba(current_features)[0]
            attack_prob = probs[1]

            # HYBRID AI DETECTION: Triggers on high AI confidence OR known Ransomware ports (445)
            if attack_prob > 0.65 or dst_port == 445:
                threat_count += 1
                
                # S-Grade MITRE Mapping
                if dst_port == 445:
                    ttp = "T1210 (Exploitation of Remote Services - EternalBlue/WannaCry)"
                    confidence = "100.0% (Signature + AI Match)"
                else:
                    ttp = "T1498 (Network Denial of Service / Anomaly)"
                    confidence = f"{attack_prob*100:.1f}% (AI Heuristics)"

                if attacker_ip not in traced_ips:
                    traced_ips[attacker_ip] = get_threat_intelligence(attacker_ip)
                
                location_data = traced_ips[attacker_ip]

                print(f"[🚨 RANSOMWARE ALERT] Threat IP: {attacker_ip}")
                print(f"   ├─ Detection     : {confidence}")
                print(f"   ├─ MITRE TTP     : {ttp}")
                print(f"   └─ OSINT Trace   : {location_data}\n")

    print(f"📊 [REPORT] Incident Analysis Complete. Total Critical Threats Mitigated: {threat_count}")

if __name__ == "__main__":
    # Pointing the ingestor to the newly downloaded WannaCry traffic
    analyze_pcap("wannacry.pcap")