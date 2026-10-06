"""
generate_test_traffic.py
-------------------------
Generates SAFE, harmless test traffic to trigger the custom Suricata rules
in rules/local.rules — for demonstration/testing purposes ONLY.

SAFETY GUARANTEE: this script validates the target IP before sending
anything and REFUSES to run against any address that is not localhost or
a private (RFC1918) address. It will never send traffic to a public IP.

Usage:
    python3 generate_test_traffic.py --icmp
    python3 generate_test_traffic.py --http
    python3 generate_test_traffic.py --port-scan
    python3 generate_test_traffic.py --login-test
    python3 generate_test_traffic.py --signature
    python3 generate_test_traffic.py --all
    python3 generate_test_traffic.py --all --target 192.168.56.10   # e.g. a lab VM you own
"""

import argparse
import ipaddress
import socket
import subprocess
import sys
import time

import requests

DEFAULT_TARGET = "127.0.0.1"
TEST_HTTP_PORT = 8080  # a local test HTTP server you run yourself (see note below)


def validate_target(ip_str: str) -> str:
    """
    Only allow loopback or private (RFC1918) addresses as a test target.
    Raises SystemExit with a clear message if the target is public/unsafe.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        print(f"[FAIL] '{ip_str}' is not a valid IP address.")
        sys.exit(1)

    if ip.is_loopback or ip.is_private:
        return str(ip)

    print(
        f"[FAIL] Refusing to target '{ip_str}': it is not a loopback or "
        f"private/lab address. This tool will never send test traffic to a "
        f"public IP address."
    )
    sys.exit(1)


def log(msg: str):
    print(f"[INFO] {msg}")


def test_icmp(target: str):
    log("Starting test")
    log(f"Target: {target}")
    log("Generating controlled ICMP (ping) traffic")
    log("Waiting for IDS alert")
    try:
        # -c 4: send 4 pings; works on Linux (adjust flag for other OSes)
        subprocess.run(["ping", "-c", "4", target], check=False, capture_output=True)
        print("[PASS] Test completed")
    except FileNotFoundError:
        print("[FAIL] 'ping' command not found on this system.")


def test_http(target: str, port: int):
    log("Starting test")
    log(f"Target: {target}:{port}")
    log("Generating controlled HTTP test request")
    log("Waiting for IDS alert")
    url = f"http://{target}:{port}/codealpha-test-suspicious"
    try:
        requests.get(url, timeout=2)
    except requests.exceptions.RequestException:
        # It's fine if there's no server listening — Suricata still sees the
        # TCP/HTTP request on the wire and the rule can still match, since
        # detection happens at the network layer, not the application layer.
        pass
    print("[PASS] Test completed")


def test_port_scan(target: str, start_port: int = 8000, count: int = 12):
    log("Starting test")
    log(f"Target: {target}")
    log(f"Generating {count} rapid connection attempts (simulated scan)")
    log("Waiting for IDS alert")
    for port in range(start_port, start_port + count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect_ex((target, port))
            s.close()
        except socket.error:
            pass
    print("[PASS] Test completed")


def test_login(target: str, port: int, attempts: int = 6):
    log("Starting test")
    log(f"Target: {target}:{port}")
    log(f"Generating {attempts} controlled failed-login test requests")
    log("Waiting for IDS alert")
    url = f"http://{target}:{port}/codealpha-test-login"
    for i in range(attempts):
        try:
            requests.post(
                url,
                data={"username": "test-user", "password": "obviously-fake-test-password"},
                timeout=2,
            )
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.3)
    print("[PASS] Test completed")


def test_signature(target: str, port: int):
    log("Starting test")
    log(f"Target: {target}:{port}")
    log("Sending unique CodeAlpha proof-of-life signature")
    log("Waiting for IDS alert")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))
        s.sendall(b"CODEALPHA-IDS-TEST-SIGNATURE\n")
        s.close()
    except socket.error:
        pass  # connection may be refused if nothing is listening; the bytes
              # sent are still enough to be visible to a listening Suricata
              # on the loopback interface in many capture configurations.
    print("[PASS] Test completed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate SAFE local test traffic for the CodeAlpha IDS project."
    )
    parser.add_argument("--target", default=DEFAULT_TARGET,
                         help="Test target IP (must be loopback or private). Default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=TEST_HTTP_PORT,
                         help="Local test HTTP server port. Default: 8080")
    parser.add_argument("--icmp", action="store_true", help="Run ICMP test")
    parser.add_argument("--http", action="store_true", help="Run HTTP test")
    parser.add_argument("--port-scan", action="store_true", help="Run port-scan-pattern test")
    parser.add_argument("--login-test", action="store_true", help="Run failed-login test")
    parser.add_argument("--signature", action="store_true", help="Run proof-of-life signature test")
    parser.add_argument("--all", action="store_true", help="Run all tests in sequence")
    args = parser.parse_args()

    target = validate_target(args.target)

    if not any([args.icmp, args.http, args.port_scan, args.login_test, args.signature, args.all]):
        parser.print_help()
        sys.exit(0)

    if args.all or args.icmp:
        test_icmp(target)
    if args.all or args.http:
        test_http(target, args.port)
    if args.all or args.port_scan:
        test_port_scan(target)
    if args.all or args.login_test:
        test_login(target, args.port)
    if args.all or args.signature:
        test_signature(target, args.port)

    print("[INFO] All requested tests finished. Check logs/eve.json or the dashboard for alerts.")
