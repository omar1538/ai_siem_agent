cat > /mnt/c/Users/omarb/ai-siem-agent/README.md << 'EOF'
# 🛡️ AI-Powered SIEM Alert Triage Agent

An autonomous AI agent that automatically investigates cybersecurity alerts like a SOC analyst.

## What it does
- Receives a security alert
- Classifies the attack type
- Checks IP reputation
- Assesses severity
- Generates a full threat report

## Stack
- Python, LangChain, Groq API (llama-3.3-70b-versatile)
- FastAPI backend
- Streamlit dashboard

## How to run
1. Clone the repo
2. Create `.env` with `GROQ_API_KEY=your_key`
3. Install dependencies: `pip install -r requirements.txt`
4. Start API: `uvicorn api.main:app --port 8000`
5. Start dashboard: `streamlit run dashboard/app.py`
EOF

cd /mnt/c/Users/omarb/ai-siem-agent
git add README.md
git commit -m "Add README"
git push
