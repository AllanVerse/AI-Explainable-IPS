# Use a lightweight, secure Linux base image
FROM ubuntu:22.04

# Stop interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install Suricata C-Engine and Python3
RUN apt-get update && apt-get install -y \
    suricata \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Set up the working directory inside the container
WORKDIR /opt/ai_ips

# Copy your ML model, scripts, and requirements
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the rest of your enterprise code
COPY . .

# Update Suricata rules
RUN suricata-update

# Start Suricata in the background, then launch the AI ChatOps bridge
# Start Suricata without Checksum Validation, then launch the AI ChatOps bridge
# Use the force-config and disable checksums (-k none)
CMD rm -f /var/run/suricata.pid && suricata -i eth0 -k none -c suricata-force.yaml -D && python3 -u enterprise_ips.py