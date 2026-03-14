# 🛡️ ThreatAnalyzer

A cybersecurity tool to analyze IPs and domains against real threat intelligence sources.

![ThreatAnalyzer Demo](docs/demo.png)

## 🔍 Features
- Analyze any IP address or domain instantly
- Threat score calculated from 70+ security engines (VirusTotal)
- Abuse confidence score (AbuseIPDB)
- Geolocation, ISP, and owner info
- Clean, dark cybersecurity-themed UI

## 🧰 Tech Stack
- **Frontend:** React + Vite
- **Backend:** PHP (secure API proxy)
- **APIs:** VirusTotal, AbuseIPDB

## ⚙️ Setup

### 1. Clone the repo
git clone https://github.com/Idrissrezx/threat-analyzer.git

### 2. Configure API keys
Create a `backend/.env` file:
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here

### 3. Run the backend
Place the `backend/` folder in your PHP server (XAMPP htdocs).

### 4. Run the frontend
cd frontend
npm install
npm run dev

## 📡 APIs Used
- [VirusTotal](https://www.virustotal.com) — 70+ antivirus engines
- [AbuseIPDB](https://www.abuseipdb.com) — IP abuse database

## 👤 Author
**Idriss Chiheb** — Cybersecurity analyst & CS Student
