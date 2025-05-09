# core/features/detect_dos.py

from scapy.all import sniff, IP
from collections import defaultdict, deque
from datetime import datetime, timedelta
from rich import print
import time, os, json, csv

# Global state
packet_history = defaultdict(deque)
average_rate_tracker = defaultdict(list)  # Stores short-term packet rates per IP

TIME_WINDOW = 1  # seconds
AVG_WINDOW = 30  # keep last 30 packet/sec samples per IP
BASELINE_MULTIPLIER = 3  # Alert if current rate exceeds 3x avg
DEFAULT_THRESHOLD = 100  # fallback if no avg yet

def log_alert(ip, rate, timestamp, log_file, log_format):
    alert_msg = {
        "timestamp": timestamp,
        "src_ip": ip,
        "packet_rate": rate,
        "alert": "Potential DoS Attack"
    }

    if log_file and log_format:
        if log_format == "log":
            with open(log_file, "a") as f:
                f.write(f"{timestamp} - {ip} - {rate} pkts/sec - Possible DoS\n")
        elif log_format == "json":
            with open(log_file, "a") as f:
                f.write(json.dumps(alert_msg) + "\n")
        elif log_format == "csv":
            write_header = not os.path.exists(log_file)
            with open(log_file, "a", newline="") as f:
                writer = csv.writer(f)
                if write_header:
                    writer.writerow(["timestamp", "src_ip", "packet_rate", "alert"])
                writer.writerow([timestamp, ip, rate, "Potential DoS Attack"])

def detect_dos_packet_handler(packet, log_file=None, log_format=None, static_threshold=None):
    if IP in packet:
        src_ip = packet[IP].src
        now = datetime.now()

        # Clean up timestamps beyond time window
        while packet_history[src_ip] and (now - packet_history[src_ip][0]).total_seconds() > TIME_WINDOW:
            packet_history[src_ip].popleft()

        # Add new timestamp
        packet_history[src_ip].append(now)
        current_rate = len(packet_history[src_ip])

        # Track moving average
        average_rate_tracker[src_ip].append(current_rate)
        if len(average_rate_tracker[src_ip]) > AVG_WINDOW:
            average_rate_tracker[src_ip].pop(0)
        avg_rate = sum(average_rate_tracker[src_ip]) / len(average_rate_tracker[src_ip])

        # Determine threshold
        adaptive_threshold = static_threshold or max(DEFAULT_THRESHOLD, BASELINE_MULTIPLIER * avg_rate)

        if current_rate > adaptive_threshold:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[bold red][!] DoS Alert:[/bold red] [cyan]{src_ip}[/cyan] → [yellow]{current_rate}[/yellow] pkts/sec (Threshold: {int(adaptive_threshold)}) at {timestamp}")
            log_alert(src_ip, current_rate, timestamp, log_file, log_format)

def start_dos_detector(iface, log_file=None, log_format=None, threshold=None):
    print("[*] Starting Advanced DoS Detector... Press Ctrl+C to stop.")
    sniff(
        prn=lambda pkt: detect_dos_packet_handler(
            pkt,
            log_file=log_file,
            log_format=log_format,
            static_threshold=threshold
        ),
        store=False,
        iface=iface
    )
