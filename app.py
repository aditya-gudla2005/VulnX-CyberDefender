from flask import Flask, render_template, jsonify, send_file, request
import json
import os
from fpdf import FPDF
from scan import scan_target  # make sure scan.py is in the same folder

app = Flask(__name__)

# === HTML Dashboard Route ===
@app.route("/")
def index():
    return render_template("index.html")

# === API Endpoint to Return Alerts as JSON ===
@app.route("/alerts")
def get_alerts():
    data = read_alerts()
    return jsonify(data)

# === Export Alerts to PDF ===
@app.route("/export-pdf")
def export_pdf():
    alerts = read_alerts()

    try:
        with open("scan_results.json", "r") as f:
            scan_data = json.load(f)
    except:
        scan_data = []

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(255, 20, 147)
    pdf.cell(200, 10, txt="VulnX Combined Report", ln=True, align="C")

    # 🧠 Sniffer Alerts
    pdf.ln(10)
    pdf.set_font("Arial", "B", 14)
    pdf.set_text_color(0, 0, 255)
    pdf.cell(0, 10, "Sniffer-Based Alerts:", ln=True)

    pdf.set_font("Arial", size=12)
    pdf.set_text_color(0, 0, 0)
    if alerts:
        for alert in alerts:
            timestamp = alert.get("timestamp", "Unknown")
            reason = alert.get("reason", "No reason")
            pdf.multi_cell(0, 10, txt=f"[{timestamp}] {reason}")
    else:
        pdf.cell(0, 10, txt="No sniffer alerts found.", ln=True)

    # 🔍 Scan Results
    pdf.ln(10)
    pdf.set_font("Arial", "B", 14)
    pdf.set_text_color(0, 150, 0)
    pdf.cell(0, 10, "Scan Results:", ln=True)

    pdf.set_font("Arial", size=12)
    pdf.set_text_color(0, 0, 0)
    if scan_data:
        for item in scan_data:
            pdf.multi_cell(0, 10, txt=json.dumps(item, indent=2))
    else:
        pdf.cell(0, 10, txt="No scan results available.", ln=True)

    pdf.output("VulnX_Report.pdf")
    return send_file("VulnX_Report.pdf", as_attachment=True)



# === Run a Scan from the Dashboard ===
@app.route("/scan", methods=["POST"])
def scan_url():
    data = request.json
    url = data.get("url")
    if not url:
        return jsonify({"status": "fail", "message": "No URL provided"}), 400

    found = scan_target(url)
    if found:
        return jsonify({"status": "ok", "message": f"✅ Found {len(found)} issue(s).", "details": found})
    return jsonify({"status": "ok", "message": "✅ Scan complete. No issues found.", "details": []})


# === Local JSON Log Loader ===
def read_alerts():
    if os.path.exists("alerts.json"):
        with open("alerts.json", "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

# === Main Entry Point ===
if __name__ == "__main__":
    app.run(debug=True, port=5000)
