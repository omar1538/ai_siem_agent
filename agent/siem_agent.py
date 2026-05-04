from langchain_groq import ChatGroq
from langchain_core.tools import tool
from dotenv import load_dotenv
import os
from datetime import datetime

load_dotenv()

llm = ChatGroq(
    api_key=os.getenv("GROQ_API_KEY"),
    model_name="llama-3.3-70b-versatile",
    temperature=0.1
)

@tool
def classify_attack_type(alert_description: str) -> str:
    """Classifies the type of cyberattack based on alert description."""
    attack_patterns = {
        "brute force": ["failed login", "multiple attempts", "password", "authentication failed"],
        "port scan": ["port scan", "nmap", "scanning", "probe"],
        "sql injection": ["sql", "injection", "database", "query"],
        "ddos": ["flood", "ddos", "denial of service", "traffic spike"],
        "malware": ["malware", "virus", "trojan", "ransomware", "suspicious process"],
        "data exfiltration": ["large transfer", "exfiltration", "unusual upload", "data transfer"],
        "lateral movement": ["lateral", "internal scan", "pivoting", "pass the hash"],
    }
    alert_lower = alert_description.lower()
    for attack_type, keywords in attack_patterns.items():
        if any(keyword in alert_lower for keyword in keywords):
            return f"Attack Type Identified: {attack_type.upper()}"
    return "Attack Type: UNKNOWN - requires manual investigation"

@tool
def check_ip_reputation(ip_address: str) -> str:
    """Checks if an IP address is known to be malicious."""
    known_malicious = ["185.234.219.45", "192.168.1.100", "10.0.0.1", "45.33.32.156"]
    private_ranges = ["192.168.", "10.", "172.16.", "127."]
    is_private = any(ip_address.startswith(r) for r in private_ranges)
    if ip_address in known_malicious:
        return f"IP {ip_address}: HIGH RISK - Known malicious IP address flagged in threat database"
    elif is_private:
        return f"IP {ip_address}: INTERNAL - Private network address, possible insider threat or lateral movement"
    else:
        return f"IP {ip_address}: UNKNOWN - Not in known malicious database, proceed with caution"

@tool
def assess_severity(alert_info: str) -> str:
    """Assesses the severity level of a security alert."""
    high_indicators = ["root", "admin", "critical", "production", "database",
                       "financial", "multiple", "persistent", "exfiltration"]
    medium_indicators = ["failed", "attempt", "scan", "probe", "unusual"]
    alert_lower = alert_info.lower()
    high_count = sum(1 for i in high_indicators if i in alert_lower)
    medium_count = sum(1 for i in medium_indicators if i in alert_lower)
    if high_count >= 2:
        return "Severity: CRITICAL - Immediate response required"
    elif high_count >= 1:
        return "Severity: HIGH - Response required within 1 hour"
    elif medium_count >= 2:
        return "Severity: MEDIUM - Response required within 4 hours"
    else:
        return "Severity: LOW - Monitor and log for patterns"

@tool
def generate_recommendations(attack_type: str) -> str:
    """Generates actionable security recommendations based on attack type."""
    recommendations = {
        "brute force": [
            "Block source IP immediately",
            "Enable account lockout policy",
            "Implement MFA for affected accounts",
            "Review authentication logs for successful logins",
            "Consider implementing fail2ban or similar tool"
        ],
        "port scan": [
            "Block scanning IP at firewall level",
            "Review exposed services and close unnecessary ports",
            "Check for subsequent exploitation attempts",
            "Update IDS/IPS signatures"
        ],
        "ddos": [
            "Enable DDoS protection/scrubbing",
            "Rate limit incoming traffic",
            "Contact ISP for upstream filtering",
            "Activate CDN protection if available"
        ],
        "default": [
            "Isolate affected systems",
            "Preserve logs for forensic analysis",
            "Notify security team immediately",
            "Document all findings and actions taken"
        ]
    }
    attack_lower = attack_type.lower()
    for key in recommendations:
        if key in attack_lower:
            recs = recommendations[key]
            return "Recommendations:\n" + "\n".join(f"- {r}" for r in recs)
    return "Recommendations:\n" + "\n".join(f"- {r}" for r in recommendations["default"])


def investigate_alert(alert: dict) -> dict:
    """Main function to investigate a security alert using the AI agent."""

    alert_description = f"""
    SECURITY ALERT
    ==============
    Time: {alert.get('timestamp', datetime.now().isoformat())}
    Source IP: {alert.get('source_ip', 'Unknown')}
    Target: {alert.get('target', 'Unknown')}
    Alert Type: {alert.get('alert_type', 'Unknown')}
    Description: {alert.get('description', 'No description provided')}
    Additional Info: {alert.get('additional_info', 'None')}
    """

    # Run tools manually - no AgentExecutor needed
    attack_result   = classify_attack_type.invoke(alert_description)
    ip_result       = check_ip_reputation.invoke(alert.get('source_ip', 'Unknown'))
    severity_result = assess_severity.invoke(alert_description)
    recommendations = generate_recommendations.invoke(attack_result)

    # Ask LLM for final report
    context = f"""
    You are an expert SOC analyst. Based on the following investigation results,
    write a professional threat report.

    ALERT:
    {alert_description}

    INVESTIGATION RESULTS:
    - {attack_result}
    - {ip_result}
    - {severity_result}
    - {recommendations}

    Write a clear, structured threat report with: Summary, Findings, Severity, and Recommended Actions.
    """

    response = llm.invoke(context)

    return {
        "alert": alert,
        "investigation": response.content,
        "timestamp": datetime.now().isoformat(),
        "analyst": "AI-SIEM-Agent v1.0"
    }
