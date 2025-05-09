# utils/device_utils.py

import os

known_devices_file = "data/known_devices.txt"

def load_known_devices():
    known = set()
    if os.path.exists(known_devices_file):
        with open(known_devices_file, "r") as f:
            for line in f:
                ip_mac = line.strip().split(",")
                if len(ip_mac) == 2:
                    known.add((ip_mac[0], ip_mac[1].lower()))
    return known

def load_blocklist(filepath="data/blocklist.txt"):
    if not os.path.exists(filepath):
        print(f"[!] Blocklist file '{filepath}' not found. Continuing with empty blocklist.")
        return set()
    with open(filepath, "r") as f:
        return set(line.strip().lower() for line in f if line.strip())
