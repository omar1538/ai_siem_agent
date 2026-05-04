from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.siem_agent import investigate_alert

app = FastAPI(
    title="AI SIEM Agent API",
    description="Autonomous cybersecurity alert triage and investigation",
    version="1.0.0"
)

class AlertRequest(BaseModel):
    alert_type: str
    source_ip: str
    destination_ip: str
    timestamp: str
    additional_info: str = ""

class AlertResponse(BaseModel):
    status: str
    report: str

@app.get("/")
def root():
    return {"message": "AI SIEM Agent is running"}

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/investigate", response_model=AlertResponse)
def investigate(alert: AlertRequest):
    try:
        report = investigate_alert({
            "alert_type": alert.alert_type,
            "source_ip": alert.source_ip,
            "target": alert.destination_ip,
            "timestamp": alert.timestamp,
            "additional_info": alert.additional_info
        })
        return AlertResponse(status="success", report=report["investigation"])
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))