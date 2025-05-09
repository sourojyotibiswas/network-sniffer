# core/features/simple_sniffer.py

from scapy.all import sniff, Ether, IP, TCP, UDP, ARP, Raw
from datetime import datetime
from rich import print
import re
import json
import csv
import os

# ---------- Color Helpers ----------
def colorize_protocol(proto):
    colors = {
        "TCP": "[green]TCP[/green]",
        "UDP": "[cyan]UDP[/cyan]",
        "ARP": "[yellow]ARP[/yellow]",
        "ICMP": "[magenta]ICMP[/magenta]",
    }
    return colors.get(proto.upper(), f"[white]{proto}[/white]")

def colorize_flags(flags):
    flag_colors = {
        'S': '[bold green]S[/bold green]',
        'A': '[bold blue]A[/bold blue]',
        'F': '[bold red]F[/bold red]',
        'P': '[yellow]P[/yellow]',
        'R': '[bold red]R[/bold red]',
        'U': '[magenta]U[/magenta]',
    }
    return ''.join(flag_colors.get(f, f) for f in flags)

# ---------- Strip Colors for Logging ----------
def remove_colors(text):
    return re.sub(r'\[/?[^\]]+\]', '', text)

# ---------- Packet Handler ----------
first_packet = True  # Used to print header only once

def simple_packet_handler(packet, log_file=None, log_format=None, filter_ip=None, filter_port=None, filter_proto=None):
    global first_packet
    timestamp = datetime.fromtimestamp(packet.time).strftime("%H:%M:%S.%f")[:-3]  # Format as HH:MM:SS.mmm

    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
    else:
        src_mac = dst_mac = "N/A"

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    else:
        src_ip = dst_ip = "N/A"

    proto = "OTHER"
    src_port = dst_port = "-"
    flags = ""
    length = len(packet)
    info = ""
    alert_msg = ""

    if TCP in packet:
        proto = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet.sprintf("%TCP.flags%")
        info = f"Seq={packet[TCP].seq} Ack={packet[TCP].ack} Win={packet[TCP].window}"

        # Detect suspicious SYN scan (SYN flag only)
        if flags == "S":
            alert_msg = f"[bold red][!] Suspicious SYN scan detected from {src_ip} to {dst_ip}[/bold red]"
            print(alert_msg)

        if Raw in packet:
            payload = bytes(packet[Raw]).decode(errors="ignore")
            if payload.startswith("GET") or payload.startswith("POST"):
                info += f" | HTTP {payload.splitlines()[0]}"
            elif "HTTP/1.1" in payload:
                info += f" | {payload.splitlines()[0]}"

    elif UDP in packet:
        proto = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif ARP in packet:
        proto = "ARP"
        info = "ARP Request/Reply"

    # Apply filters
    if filter_proto and proto.lower() not in [p.lower() for p in filter_proto]:
        return
    if filter_ip and (src_ip != filter_ip and dst_ip != filter_ip):
        return
    if filter_port and (src_port != filter_port and dst_port != filter_port):
        return

    formatted_proto = colorize_protocol(proto)
    formatted_flags = colorize_flags(flags)

    if first_packet:
        print("[bold]Time           Source           → Destination      Proto  Length  Info[/bold]")
        first_packet = False

    output = (
        f"{timestamp} | {src_ip} → {dst_ip} | {formatted_proto} {src_port} → {dst_port} {formatted_flags} | {length} bytes | {info}"
    )
    print(output)

    # Logging
    if log_file and log_format:
        clean_output = remove_colors(output)
        if log_format == "log":
            with open(log_file, "a") as f:
                f.write(clean_output + "\n")
        elif log_format == "json":
            log_entry = {
                "timestamp": timestamp,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags": flags,
                "length": length,
                "info": info,
                "alert": "SYN scan detected" if alert_msg else ""
            }
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        elif log_format == "csv":
            write_header = not os.path.exists(log_file)
            with open(log_file, "a", newline="") as f:
                writer = csv.writer(f)
                if write_header:
                    writer.writerow([
                        "timestamp", "src_mac", "dst_mac", "src_ip", "dst_ip",
                        "protocol", "src_port", "dst_port", "flags", "length", "info"
                    ])
                writer.writerow([
                    timestamp, src_mac, dst_mac, src_ip, dst_ip, proto,
                    src_port, dst_port, flags, length, info
                ])

# ---------- Sniffer Start ----------
def start_simple_sniffer(iface, log_file=None, log_format=None, filter_ip=None, filter_port=None, filter_proto=None):
    print("[*] Starting Simple Sniffer... Press Ctrl+C to stop.")
    sniff(
        prn=lambda pkt: simple_packet_handler(
            pkt,
            log_file=log_file,
            log_format=log_format,
            filter_ip=filter_ip,
            filter_port=filter_port,
            filter_proto=filter_proto
        ),
        store=False,
        iface=iface
    )
