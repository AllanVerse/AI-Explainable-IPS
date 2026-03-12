import subprocess

def apply_defense(ip, action):
    # SAFETY SWITCH FOR DEMO
    is_localhost = (ip == "127.0.0.1")

    if action == "BLOCK_PERMANENT":
        if is_localhost:
            print(f"🛑 [DEMO SAFE] Simulated PERMANENT BLOCK for {ip} (Firewall bypass to prevent WSL crash).")
        else:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            print(f"🚫 PERMANENT BLOCK: {ip} added to Firewall.")

    elif action == "DECEPTION_REDIRECT":
        if is_localhost:
            print(f"🎭 [DEMO SAFE] Simulated HONEYPOT REDIRECT for {ip}.")
        else:
            subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-s", ip, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8080"])
            print(f"🎭 DECEPTION: {ip} redirected to Honeypot.")

    elif action == "HITL_REVIEW":
        print(f"⚠️ HITL: Low confidence detection for {ip}. Logged for Human Review.")