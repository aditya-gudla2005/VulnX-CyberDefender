from scapy.all import sniff, Raw
from urllib.parse import unquote
from datetime import datetime
import re
import requests
import sys
import json
import os


TELEGRAM_BOT_TOKEN = "7828185542:AAFyuYorqj48upv1CJRNxvjhR6Lyz0XlH1Q"
TELEGRAM_CHAT_ID = "1378255919"

# === Signature Patterns ===
XSS_SIGNS = [r"<script>", r"<img.*onerror=.*>", r"alert\(", r"onerror=", r"<svg.*onload=.*>"]
SQLI_SIGNS = [r"' OR '1'='1", r"'--", r"(?i)select .* from", r"(?i)union select", r"1=1", r"sleep\("]

# === Logger Function ===
def log_suspicious(pkt, reason):
    src = pkt[0][1].src if pkt.haslayer("IP") else "Unknown"
    log_entry = f"[{datetime.now()}] Suspicious packet from {src}: {reason}"
    print(f"[ALERT] {log_entry}")

    with open("suspicious_packets.log", "a") as f:
        f.write(log_entry + "\n")

    append_to_json(log_entry, reason)
    send_telegram_alert(log_entry)

    
def append_to_json(log_entry, reason):
    filename = "alerts.json"
    data = []

    if os.path.exists(filename):
        try:
            with open(filename, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            pass  # If file is empty or corrupt

    data.append({
        "timestamp": str(datetime.now()),
        "reason": reason,
        "entry": log_entry
    })

    with open(filename, "w") as f:
        json.dump(data, f, indent=2)

# === Packet Analyzer ===
def analyze_packet(packet):
    if packet.haslayer(Raw):
        raw_payload = packet[Raw].load.decode(errors="ignore")
        decoded = unquote(raw_payload)

        print("[*] Decoded payload:", decoded[:150])
        print("[DEBUG] Raw payload:", raw_payload[:150])

        # XSS check
        for pattern in XSS_SIGNS:
            if re.search(pattern, decoded, re.IGNORECASE):
                print(f"[MATCH] XSS pattern detected: {pattern}")
                log_suspicious(packet, "Potential XSS")
                return

        # SQLi check
        for pattern in SQLI_SIGNS:
            if re.search(pattern, decoded, re.IGNORECASE):
                print(f"[MATCH] SQLi pattern detected: {pattern}")
                log_suspicious(packet, "Potential SQL Injection")
                return

# === Sniffer ===
def start_sniffing(interface="eth0"):
    print(f"[*] Sniffing on {interface}... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=analyze_packet, store=False)

def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message
    }
    try:
        requests.post(url, data=data)
    except Exception as e:
        print(f"[!] Telegram send failed: {e}")
# === Entry Point ===
if __name__ == "__main__":
    try:
        iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
        start_sniffing(iface)
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user.")
