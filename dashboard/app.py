import streamlit as st
import requests
from datetime import datetime

st.set_page_config(
    page_title="AI SIEM Agent",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI-Powered SIEM Alert Triage")
st.markdown("Submit a security alert and get an automated threat investigation report.")

with st.form("alert_form"):
    col1, col2 = st.columns(2)

    with col1:
        alert_type = st.selectbox("Alert Type", [
            "Brute Force Attack",
            "SQL Injection",
            "DDoS Attack",
            "Port Scan",
            "Malware Detection",
            "Phishing Attempt",
            "Unauthorized Access"
        ])
        source_ip = st.text_input("Source IP", value="192.168.1.1")

    with col2:
        destination_ip = st.text_input("Destination IP", value="10.0.0.1")
        timestamp = st.text_input("Timestamp", value=str(datetime.now()))

    additional_info = st.text_area("Additional Info", 
                                    value="Multiple failed login attempts detected")

    submitted = st.form_submit_button("🔍 Investigate Alert")

if submitted:
    with st.spinner("AI Agent is investigating the alert..."):
        try:
            response = requests.post(
                "http://0.0.0.0:8000/investigate",
                json={
                    "alert_type": alert_type,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "timestamp": timestamp,
                    "additional_info": additional_info
                }
            )
            if response.status_code == 200:
                report = response.json()["report"]
                st.success("✅ Investigation Complete!")
                st.markdown("### 📋 Threat Report")
                st.markdown(report)
            else:
                st.error(f"Error: {response.text}")
        except Exception as e:
            st.error(f"Could not connect to API: {e}")