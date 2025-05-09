import typer
from core.utils.banner import banner

from core.features.http_https_sniffer import start_combined_sniffer
from core.features.mac_tracker import start_mac_tracker
from core.features import detect_dos

from scapy.all import sniff

app = typer.Typer(help="🕵️ Packet Sniffer CLI Tool")

# ==================================================================================================

@app.command("sniff-simple")
def sniff_simple(
    iface: str = typer.Option(..., "--iface", "-i", help="Interface to sniff on"),
    log_format: str = typer.Option(None, "--log-format", "-l", help="Optional log format: log, json, csv"),
    log_file: str = typer.Option(None, "--log-file", "-lf", help="Optional log file path: example.json"),
    filter_ip: str = typer.Option(None, "--filter-ip", "-fip", help="Only capture packets from/to this IP"),
    filter_port: int = typer.Option(None, "--filter-port", "-fpo", help="Only capture packets from/to this port"),
    filter_proto: str = typer.Option(
        None,
        "--filter-protocol", "-fpt",
        help="Only capture packets of specified protocols (comma-separated, e.g., tcp,udp,arp)"
    )
):
    """Sniff all the packets flowing through your network."""
    allowed_formats = ["log", "json", "csv"]
    if log_format and log_format not in allowed_formats:
        print(f"[!] Invalid format '{log_format}'. Choose from: {', '.join(allowed_formats)}")
        raise typer.Exit(code=1)

    if log_format and not log_file:
        log_file = f"sniff_output.{log_format}"

    if log_file and log_format:
        if not log_file.endswith(f".{log_format}"):
            print(f"[!] Log file extension does not match format. Use a .{log_format} extension.")
            raise typer.Exit(code=1)

    proto_list = [p.strip().lower() for p in filter_proto.split(",")] if filter_proto else None

    from core.features.simple_sniffer import start_simple_sniffer
    start_simple_sniffer(
        iface=iface,
        log_file=log_file,
        log_format=log_format,
        filter_ip=filter_ip,
        filter_proto=proto_list,
        filter_port=filter_port
    )

# ==================================================================================================

@app.command("sniff-combined")
def sniff_combined(iface: str = typer.Option(..., "--iface", "-i", help="Interface to sniff on")):
    """Sniff HTTP/HTTPS traffic and show sensitive requests."""
    start_combined_sniffer(iface)

# ==================================================================================================

@app.command("sniff-mac")
def mac_tracker(
    iface: str = typer.Option(..., "--iface", "-i", help="Interface to sniff on"),
    subnet: str = typer.Option(..., "--subnet", "-s", help="Target subnet to scan (e.g., 192.168.92.0/24)"),
    log_format: str = typer.Option(
        None,
        "--log-format",
        "-l",
        help="Optional log format: log, json, csv"
    ),
    log_file: str = typer.Option(None, "--log-file", "-lf", help="Optional log file path: example.json")
):
    """
    Track known and unknown MAC addresses via ARP.
    """
    valid_formats = {"log", "json", "csv"}
    if log_format and log_format.lower() not in valid_formats:
        typer.echo("[!] Invalid log format. Choose from: log, json, csv")
        raise typer.Exit(1)

    start_mac_tracker(iface, subnet, log_file, log_format.lower() if log_format else None)

@app.command("list-ifaces")
def list_ifaces():
    """
    List all available network interfaces.
    """
    import psutil
    interfaces = psutil.net_if_stats()
    print("[*] Available Network Interfaces:")
    for iface, stats in interfaces.items():
        status = "UP" if stats.isup else "DOWN"
        typer.echo(f"  - {iface} [{status}]")

@app.command("detect-dos")
def detect_dos(
    iface: str = typer.Option(..., "--iface", "-i", help="Interface to monitor"),
    log_file: str = typer.Option(None, "--log-file", "-lf", help="Optional log file path"),
    log_format: str = typer.Option(None, "--log-format", "-l", help="Format: log, json, csv"),
    threshold: int = typer.Option(None, "--threshold", "-t", help="Override adaptive threshold with fixed value")
):
    """
    Detect high packet rate (possible DoS) from a source IP using adaptive thresholding.
    """
    from core.features import detect_dos
    detect_dos.start_dos_detector(iface, log_file, log_format, threshold)

if __name__ == "__main__":
    app()
