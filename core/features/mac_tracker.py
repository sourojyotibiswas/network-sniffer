# core/features/mac_tracker.py

from scapy.all import ARP, Ether, srp, sniff
from core.utils.known_devices_loader import load_known_devices, seen_devices
from rich import print
from datetime import datetime
import os
import json
import csv
import re

known_devices = load_known_devices()

def get_timestamp():
    return datetime.now().strftime('%H:%M:%S')

def remove_colors(text):
    return re.sub(r'\[/?[^\]]+\]', '', text)

def log_mac_activity(log_file, log_format, timestamp, ip, mac, status):
    if not log_file or not log_format:
        return

    if log_format == "log":
        with open(log_file, "a") as f:
            f.write(f"[{timestamp}] {status.upper()} - {ip} -> {mac}\n")

    elif log_format == "json":
        log_entry = {
            "timestamp": timestamp,
            "ip": ip,
            "mac": mac,
            "status": status
        }
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    elif log_format == "csv":
        write_header = not os.path.exists(log_file)
        with open(log_file, "a", newline="") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow(["timestamp", "ip", "mac", "status"])
            writer.writerow([timestamp, ip, mac, status])

def active_arp_scan(iface, target_ip, log_file=None, log_format=None):
    print(f"[bold cyan][*][/bold cyan] Performing active ARP scan to discover devices...")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    ans, _ = srp(pkt, timeout=2, iface=iface, verbose=0)

    for _, received in ans:
        ip = received.psrc
        mac = received.hwsrc.lower()
        device = (ip, mac)
        timestamp = get_timestamp()

        if device not in seen_devices:
            seen_devices.add(device)
            if device in known_devices:
                print(f"[bold blue]{timestamp}[/bold blue] [green][KNOWN][/green]   {ip} → [bold]{mac}[/bold]")
                log_mac_activity(log_file, log_format, timestamp, ip, mac, "known")
            else:
                print(f"[bold blue]{timestamp}[/bold blue] [yellow][NEW][/yellow]     [bold magenta]{ip}[/bold magenta] → [bold red]{mac}[/bold red] [red][UNKNOWN DEVICE][/red]")
                log_mac_activity(log_file, log_format, timestamp, ip, mac, "new")

def passive_arp_monitor(packet, log_file=None, log_format=None):
    if packet.haslayer(ARP) and packet[ARP].op in (1, 2):  # ARP Request/Reply
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc.lower()
        device = (ip, mac)
        timestamp = get_timestamp()

        if device not in seen_devices:
            seen_devices.add(device)
            if device in known_devices:
                print(f"[bold blue]{timestamp}[/bold blue] [green][KNOWN][/green]   {ip} → [bold]{mac}[/bold]")
                log_mac_activity(log_file, log_format, timestamp, ip, mac, "known")
            else:
                print(f"[bold blue]{timestamp}[/bold blue] [yellow][NEW][/yellow]     [bold magenta]{ip}[/bold magenta] → [bold red]{mac}[/bold red] [red][UNKNOWN DEVICE][/red]")
                log_mac_activity(log_file, log_format, timestamp, ip, mac, "new")

def start_mac_tracker(iface, target_subnet, log_file=None, log_format=None):
    print(f"[bold cyan][*][/bold cyan] Starting MAC Tracker...")
    active_arp_scan(iface, target_subnet, log_file, log_format)
    print(f"[bold cyan][*][/bold cyan] Starting passive MAC tracking... Press Ctrl+C to stop.")
    sniff(
        filter="arp",
        prn=lambda pkt: passive_arp_monitor(pkt, log_file, log_format),
        store=False,
        iface=iface
    )
