# PhishGuard — AI-Powered Phishing Detection System

PhishGuard is an AI-powered cybersecurity application that detects potentially malicious URLs and email content using machine learning and real-time reputation checks.

### Features
- **ML-based detection:** Uses a Random Forest classifier with 33 extracted features.
- **Reputation checks:** Integrates VirusTotal and Google Safe Browsing.
- **Risk scoring:** Combines available signals to generate a risk score and verdict.
- **User authentication:** Uses JWT-based authentication.
- **Scan history:** Stores scan results in MongoDB.

### Tech Stack
- **Frontend:** React, Vite
- **Backend:** Python, FastAPI
- **Machine Learning:** Scikit-learn, Random Forest
- **Database:** MongoDB
- **Security:** JWT, bcrypt
- **External APIs:** VirusTotal, Google Safe Browsing

### Project Structure
- `backend/` — API, authentication, ML model, and detection logic
- `frontend/` — React user interface
- `backend/tests/` — Backend tests

### Setup
See `.env.example` for the required environment variables. Install the backend dependencies using `pip install -r requirements.txt` from the backend directory and the frontend dependencies using `npm install` from the frontend directory.

Configure your environment variables before starting the application. Never commit real API keys or secrets.
