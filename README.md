# 🛡️ CyberSentinel: Real-Time NPM Supply Chain Scanner

**CyberSentinel** is an automated DevSecOps tool that audits NPM dependencies for supply-chain risks in real-time by querying Google's live OSV (Open Source Vulnerabilities) database.

## 🚀 The Problem
Modern applications rely on hundreds of open-source packages. A single outdated or compromised dependency (like the famous `lodash` Prototype Pollution or the `colors.js` sabotage) can compromise an entire enterprise. Manual auditing is slow and prone to human error.

## 💡 The Solution
CyberSentinel provides an asynchronous, high-speed API and an interactive dashboard to instantly calculate a 0-100 risk score for any NPM package, flagging known CVEs, deprecated code, and low-download anomalies.

## 🛠️ Tech Stack
- **Backend:** FastAPI & Pydantic (Asynchronous validation and routing)
- **Data Ingestion:** HTTPX (Non-blocking queries to the OSV API)
- **Frontend:** Streamlit & Plotly (Real-time threat intelligence visualization)
- **Infrastructure:** Hosted on a custom Azure Linux VM

## ⚙️ How to Run Locally
1. Clone the repository: `git clone <your-repo-url>`
2. Install dependencies: `pip install -r requirements.txt`
3. Start the FastAPI backend: `uvicorn main:app --host 0.0.0.0 --port 8000`
4. Launch the Streamlit dashboard: `streamlit run dashboard.py --server.port 8501`

## 📊 Features
- Real-time CVE detection via Google OSV API
- Exponential backoff and retry logic for API resilience
- Interactive, color-coded Plotly risk dashboards
- Fully asynchronous architecture for high-throughput scanning
