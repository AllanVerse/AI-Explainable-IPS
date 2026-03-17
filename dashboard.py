import streamlit as st
import pandas as pd
import time
import os
import json

st.set_page_config(page_title="Vanguard XDR Dashboard", layout="wide", page_icon="🛡️")

st.title("🛡️ Vanguard XDR: AI-IPS Live Monitor")
st.markdown("---")

# Sidebar Status
st.sidebar.header("System Health")
st.sidebar.success("AI Matrix: ONLINE")
st.sidebar.info("Suricata: CAPTURING")
st.sidebar.warning("Active Defense: ENABLED")

# Placeholders for dynamic data
col1, col2 = st.columns(2)
with col1:
    st.subheader("Live Threat Stream")
    table_placeholder = st.empty()
with col2:
    st.subheader("AI Confidence Score")
    chart_placeholder = st.empty()

# Path to the logs
LOG_FILE = "logs/threat_history.json"

while True:
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
            data = [json.loads(line) for line in lines]
            df = pd.DataFrame(data)
            
            # Update Table
            table_placeholder.dataframe(df.tail(10), use_container_width=True)
            
            # Update Chart
            if "ai_score" in df.columns:
                chart_placeholder.line_chart(df["ai_score"].tail(20))
    else:
        st.info("Waiting for first threat detection...")
    
    time.sleep(1)
