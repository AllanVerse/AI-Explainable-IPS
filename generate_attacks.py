from scapy.all import wrpcap, IP, TCP, UDP
import random

def generate_enterprise_traffic(filename="real_malware_traffic.pcap"):
    print("🏭 [DATA GENERATOR] Forging Enterprise-Scale Traffic...")
    packets = []
    
    # 1. Generate 500 Normal "Safe" Packets (Web Browsing)
    print("[-] Generating standard user traffic...")
    for _ in range(500):
        src_ip = f"192.168.1.{random.randint(2, 100)}"
        pkt = IP(src=src_ip, dst="10.0.0.5") / TCP(dport=random.choice([80, 443]), sport=random.randint(1024, 65535))
        packets.append(pkt)

    # 2. Generate 500 Malicious Packets (Data Exfiltration / Botnet)
    # NOTICE THE TEXT CHANGE HERE:
    print("[!] Generating malicious C2 traffic (MITRE T1041)...")
    for _ in range(500):
        src_ip = f"185.156.177.{random.randint(1, 255)}" 
        # Using Port 4444 (Suspicious) and UDP (Often used for DDoS/Exfiltration)
        pkt = IP(src=src_ip, dst="10.0.0.5") / UDP(dport=4444, sport=random.randint(1024, 65535))
        # Add a MASSIVE payload to trigger the 'Pkt Len Max' feature in your AI
        pkt = pkt / (b"X" * random.randint(2000, 5000)) 
        packets.append(pkt)

    random.shuffle(packets)
    wrpcap(filename, packets)
    print(f"✅ Success: 1,000 Heavy packets saved to '{filename}'.")

if __name__ == "__main__":
    generate_enterprise_traffic()