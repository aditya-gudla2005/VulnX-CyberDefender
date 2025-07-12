# VulnX-CyberDefender
VulnX is a full-stack cybersecurity tool built to detect web vulnerabilities in real-time using live packet sniffing and manual scanning. It features a dynamic Flask-based dashboard with statistical graphs, PDF export, and optional Telegram bot alerts.

## Features

- **Live Packet Sniffing** (Scapy)
  - Detects suspicious payloads like XSS and SQLi in real-time.
  - Alerts shown instantly on the dashboard and/or via Telegram bot.

- **Manual Vulnerability Scanner**
  - Crawls a target website and tests for:
    - **XSS (Cross-Site Scripting)**
    - **SQL Injection**
  - Displays detailed scan results and saves them locally.

- **Cyberpunk-Style Dashboard**
  - View, filter, and refresh alerts.
  - Interactive graphs for alert statistics.
  - PDF export of both sniffer and scan results.

- **Offline Logging**
  - All alerts are stored in `alerts.json` and `scan_results.json`.

- **Telegram Bot Integration**
  - Get instant Telegram alerts when suspicious activity is detected.

## Technologies Used

- Python (Flask, Scapy, Requests, FPDF, BeautifulSoup)
- HTML5 + CSS3 + Chart.js
- Telegram Bot API

## Getting Started

1)**Install dependencies**
pip install -r requirements.txt

2)**Start Sniffer:**
sudo python3 sniffer.py

3)**Run Dashboard:**
python3 app.py

4)**Scan a Website**
Use the scan input field in the dashboard or run directly:
python3 scan.py

## Telegram Alert Setup:
1)Create a bot via @BotFather.

2)Replace TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in sniffer.py.

## Project Structure

├── app.py                 # Flask backend for dashboard

├── sniffer.py             # Real-time packet sniffer + detector

├── scan.py                # Manual vulnerability scanner

├── alerts.json            # Logs for real-time alerts

├── scan_results.json      # Logs for scanner-based results

├── templates/

│   └── index.html         # Dashboard UI

├── static/

│   └── style.css          # Cyberpunk-themed styles

└── VulnX_Report.pdf       


## Skipped: IP Blocking
We initially planned to add an IP blocking feature directly from the dashboard. However, to test this locally would mean self-blocking the host machine, thereby losing access to the dashboard. So this feature is documented but intentionally left out for safety.

## Future Enhancements
1)Real IP geolocation in alerts

2)Advanced vulnerability signatures

3)Remote deployment on cloud/VPS (e.g., Render, Heroku)



