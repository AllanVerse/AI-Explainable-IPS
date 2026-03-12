# X-IPS: Explainable Intrusion Prevention System with Stateful Threat Intelligence

Traditional Intrusion Prevention Systems (IPS) operate as "black boxes" and rely on outdated static signatures. **X-IPS** is a next-generation, AI-driven framework that leverages Machine Learning (Random Forest) for zero-day threat detection and **SHAP (Shapley Additive Explanations)** to provide real-time transparency for every mitigation action.

This project goes beyond standard detection by implementing a **Defense-in-Depth** architecture, featuring stateful threat tracking, confidence-based mitigation, and an active deception honeypot.

## 🚀 Key Innovative Features

* **Explainable AI (XAI):** Uses SHAP to extract the exact network feature (e.g., Packet Length, Destination Port) that triggered the AI, solving the "False Positive" trust issue.
* **Stateful Threat Memory:** Maintains a historical JSON database of attacker behavior. It recognizes persistent threats (like "Low-and-Slow" Brute Force attacks) over time and escalates the response dynamically.
* **Active Deception (Honeypot):** Instead of immediately dropping low-confidence threats, the system uses `iptables` NAT routing to transparently redirect suspicious actors to a Flask-based decoy environment (Port 8080) to safely monitor their behavior.
* **Human-in-the-Loop (HITL):** Packets falling into the AI's "uncertainty zone" (40%-70% confidence) are flagged for human review rather than executing a hard block.

## 🧠 System Architecture

The framework is built on a modular Micro-Kernel architecture to ensure low-latency packet processing:

1.  **Data Acquisition Layer (`live_ips.py`):** Utilizes `Scapy` for high-speed, raw socket packet interception directly from the network interface.
2.  **Intelligence Layer (`threat_intel.py`):** The Random Forest classifier generates a threat probability score. The History Engine correlates this with previous attack patterns.
3.  **Mitigation Layer (`mitigator.py` & `honeypot.py`):** Executes OS-level firewall commands (`iptables`) to either Drop, Redirect (Deception), or Log the traffic based on the Intelligence Layer's directive.

## 🛠️ Technology Stack

* **Core Language:** Python 3.12
* **Networking/Packet Analysis:** Scapy
* **Machine Learning:** Scikit-Learn (Random Forest)
* **XAI Engine:** SHAP (Shapley Additive Explanations)
* **System/Firewall:** Linux/WSL2, IPTables
* **Deception Service:** Flask

## ⚙️ How to Run the Framework

**1. Initialize the Threat Memory**
Populate the historical database with known attack patterns:
```bash
python3 seed_data.py