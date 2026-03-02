"""
Eyal Kaghanovich
A port scanner meant to imitate nmap functionality
6.19
"""

import sys
import socket
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sr1
from scapy.config import conf

conf.verb = 0

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
]

COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 161, 162, 500, 514, 1194, 5353]


def get_service_name(port: int, proto: str = "tcp") -> str:
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(1.0)
            # Services that speak first (SSH, FTP, SMTP …)
            try:
                data = s.recv(1024)
                if data:
                    return data.decode(errors="replace").split("\n")[0].strip()[:80]
            except socket.timeout:
                pass
            # Services that listen first (HTTP …)
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                s.settimeout(timeout)
                data = s.recv(1024)
                return data.decode(errors="replace").split("\n")[0].strip()[:80]
            except OSError:
                pass
    except OSError:
        pass
    return ""


def detect_os(target_ip: str) -> str:
    try:
        resp = sr1(IP(dst=target_ip) / ICMP(), timeout=2)
    except PermissionError:
        return "Unknown (raw socket requires root)"
    if not resp:
        return "Unknown (no ICMP response)"
    ttl = resp.ttl
    if ttl <= 64:
        return f"Linux / macOS  (TTL={ttl})"
    if ttl <= 128:
        return f"Windows        (TTL={ttl})"
    return f"Cisco / Network device  (TTL={ttl})"


# ── scan functions ────────────────────────────────────────────────────────────

def syn_scan(target_ip: str, port: int, results: dict, lock: threading.Lock) -> None:
    resp = sr1(IP(dst=target_ip) / TCP(dport=port, flags="S"), timeout=2)
    if resp and resp.haslayer(TCP):
        status = "open" if resp[TCP].flags == "SA" else "closed"
    elif resp is None:
        status = "filtered"
    else:
        status = "closed"
    with lock:
        results[port] = status


def tcp_connect_scan(target_ip: str, port: int, results: dict, lock: threading.Lock) -> None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        status = "open" if s.connect_ex((target_ip, port)) == 0 else "closed"
        s.close()
    except OSError:
        status = "closed"
    with lock:
        results[port] = status


def udp_scan(target_ip: str, port: int, results: dict, lock: threading.Lock) -> None:
    resp = sr1(IP(dst=target_ip) / UDP(dport=port), timeout=2)
    if resp is None:
        status = "open|filtered"
    elif resp.haslayer(ICMP) and int(resp[ICMP].type) == 3 and int(resp[ICMP].code) == 3:
        status = "closed"
    else:
        status = "open|filtered"
    with lock:
        results[port] = status


# ── helpers ───────────────────────────────────────────────────────────────────

def parse_ports(port_spec: str) -> list[int]:
    ports: list[int] = []
    for part in port_spec.split(","):
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ek-PortScanner",
        description="A TCP/UDP port scanner inspired by nmap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan types:
  -sS    TCP SYN scan — stealth, requires root  [default]
  -sT    TCP connect scan — no root needed
  -sU    UDP scan — requires root

Port specification:
  -p 80            single port
  -p 1-1024        port range
  -p 80,443,8080   comma-separated list
  -p 80,8080-8090  mixed

Examples:
  python3 main.py 192.168.1.1 -sS -p 1-1024
  python3 main.py 192.168.1.1 -sT -p 80,443,8080
  python3 main.py 192.168.1.1 -sU -p 53,161
  python3 main.py 192.168.1.1            # common ports, SYN scan
""",
    )
    parser.add_argument("target", help="Target IP address or hostname")

    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument(
        "-sS", dest="scan_type", action="store_const", const="sS",
        help="TCP SYN scan (stealth, requires root) [default]",
    )
    scan_group.add_argument(
        "-sT", dest="scan_type", action="store_const", const="sT",
        help="TCP connect scan (no root needed)",
    )
    scan_group.add_argument(
        "-sU", dest="scan_type", action="store_const", const="sU",
        help="UDP scan (requires root)",
    )

    parser.add_argument(
        "-p", dest="ports", type=str, default=None,
        help="Ports to scan: 80 | 1-1024 | 80,443,8080  (default: common ports)",
    )
    parser.add_argument(
        "--threads", dest="threads", type=int, default=100,
        help="Number of parallel threads (default: 100)",
    )

    args = parser.parse_args()
    scan_type: str = args.scan_type or "sS"
    is_udp = scan_type == "sU"
    proto = "udp" if is_udp else "tcp"

    ports = parse_ports(args.ports) if args.ports else (COMMON_UDP_PORTS if is_udp else COMMON_PORTS)

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Could not resolve hostname: {args.target}")
        sys.exit(1)

    print(f"\nScanning {args.target} ({target_ip})")
    print(f"Scan type : -{scan_type}  |  Ports: {len(ports)}")

    os_info = detect_os(target_ip)
    print(f"OS guess  : {os_info}\n")

    results: dict[int, str] = {}
    lock = threading.Lock()
    scan_fn = {"sS": syn_scan, "sT": tcp_connect_scan, "sU": udp_scan}[scan_type]

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for port in ports:
            executor.submit(scan_fn, target_ip, port, results, lock)

    print(f"{'PORT':<12}{'STATE':<16}{'SERVICE':<15}VERSION / BANNER")
    print("-" * 72)

    open_count = 0
    for port in sorted(results):
        status = results[port]
        if "open" in status:
            open_count += 1
            service = get_service_name(port, proto)
            banner = grab_banner(target_ip, port) if not is_udp else ""
            print(f"{f'{port}/{proto}':<12}{status:<16}{service:<15}{banner}")

    print(f"\n{open_count} open port(s) found out of {len(ports)} scanned.")


if __name__ == "__main__":
    main()

