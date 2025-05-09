# core/features/http_https_sniffer.py

from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.all import TLSClientHello

def combined_http_https_sniffer(packet):
    # Handle HTTP packets
    if packet.haslayer(Raw) and packet.haslayer(TCP):
        try:
            payload = packet[Raw].load.decode(errors="ignore")
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if payload.startswith("GET") or payload.startswith("POST"):
                lines = payload.split("\r\n")
                request_line = lines[0]  # e.g., "POST /login HTTP/1.1"
                host = next((line.split(": ")[1] for line in lines if line.lower().startswith("host:")), "unknown")

                method, path, _ = request_line.split()
                url = f"{host}{path}"

                sensitive_paths = ["/login", "/admin", "/signup", "/register"]
                is_sensitive = any(path.lower().startswith(p) for p in sensitive_paths)

                if is_sensitive:
                    print(f"[+] SENSITIVE {src_ip} -> {dst_ip} | {method} {path} | Host: {host}")
                else:
                    print(f"[HTTP] {src_ip} -> {dst_ip} | {method} {path} | Host: {host}")

                if method == "POST":
                    post_data = payload.split("\r\n\r\n", 1)
                    if len(post_data) == 2:
                        body = post_data[1]
                        if "username=" in body and "password=" in body:
                            print(f"[+] Credentials Found in POST from {src_ip} -> {dst_ip}")
                            print(f"    [+] Data: {body}")
        except Exception as e:
            print(f"[!] Error processing HTTP packet: {e}")

    # Handle HTTPS SNI
    if packet.haslayer(TLSClientHello):
        ip_layer = packet.getlayer(IP)
        client_hello = packet.getlayer(TLSClientHello)

        for ext in client_hello.ext:
            if hasattr(ext, "servernames"):  # SNI extension
                for servername in ext.servernames:
                    try:
                        sni = servername.servername.decode()
                        print(f"[HTTPS] {ip_layer.src} -> {ip_layer.dst} | SNI: {sni}")
                    except Exception as e:
                        print(f"[!] Failed to decode SNI: {e}")

def start_combined_sniffer(iface):
    print("[*] Starting Combined HTTP/HTTPS Sniffer... Press Ctrl+C to stop.")
    sniff(filter="tcp port 80 or tcp port 443", prn=combined_http_https_sniffer, store=False, iface=iface)
