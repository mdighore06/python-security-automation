#!/usr/bin/env python3
"""
Task 1: Multithreaded Port Scanner with Banner Grabbing
Usage: python port_scanner.py <target_ip> <start_port> <end_port>
"""

import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

# THREADING LOCK USAGE: Acquire lock before modifying the shared global list 
# or printing to stdout to prevent output interleaving and race conditions.
print_lock = threading.Lock()
open_ports = []


def grab_banner(sock: socket.socket) -> str:
    """Attempts banner grabbing by sending a generic probe."""
    try:
        # Send generic probe (\r\n) to trigger service response
        sock.sendall(b"\r\n")
        # BANNER DECODING: Receive up to 1024 bytes and decode using utf-8 with 'ignore'
        # errors mode to safely handle raw binary strings from unknown services.
        data = sock.recv(1024)
        return data.decode("utf-8", errors="ignore").strip()
    except (socket.timeout, socket.error):
        return "No banner"


def scan_port(ip: str, port: int, timeout: float = 1.0):
    """Scans a single TCP port with a configurable timeout."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # TIMEOUT RATIONALE: A 1.0-second timeout provides an optimal balance between
            # waiting for high-latency network routes and finishing scans quickly.
            sock.settimeout(timeout)

            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(sock)

                with print_lock:
                    open_ports.append((port, "OPEN", banner if banner else "No banner"))
    except (socket.error, socket.timeout, OSError):
        # Gracefully swallow connection refused, timeout, and OS errors without crashing
        pass


def main():
    if len(sys.argv) != 4:
        print("Usage: python port_scanner.py <target_ip> <start_port> <end_port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    try:
        start_port = int(sys.argv[2])
        end_port = int(sys.argv[3])
    except ValueError:
        print("[-] Error: Ports must be integers.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Starting scan on target: {target_ip} (Ports {start_port}-{end_port})")

    # Limit maximum worker threads to 100 to prevent local OS socket exhaustion
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, target_ip, port)

    open_ports.sort(key=lambda x: x[0])

    print("\n" + "=" * 65)
    print(f"{'Port':<10} | {'State':<10} | {'Banner'}")
    print("=" * 65)
    for p, state, banner in open_ports:
        print(f"{p:<10} | {state:<10} | {banner}")
    print("=" * 65)


if __name__ == "__main__":
    main()
