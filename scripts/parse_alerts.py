"""
parse_alerts.py
----------------
Reads Suricata's eve.json log, extracts "alert" events, normalizes the
fields we care about, and stores them in the SQLite database via database.py.

Usage:
    python3 parse_alerts.py --once            # parse the whole file once and exit
    python3 parse_alerts.py --watch           # tail the file and parse new alerts continuously
    python3 parse_alerts.py --once --file path/to/eve.json
"""

import argparse
import hashlib
import json
import os
import time
import sys

import database

DEFAULT_EVE_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "eve.json")


def normalize_event(event: dict) -> dict | None:
    """Convert a raw Suricata eve.json 'alert' event into our normalized schema."""
    if event.get("event_type") != "alert":
        return None

    alert = event.get("alert", {})
    raw = json.dumps(event, sort_keys=True)
    event_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    return {
        "timestamp": event.get("timestamp"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "signature": alert.get("signature"),
        "signature_id": alert.get("signature_id"),
        "severity": alert.get("severity"),
        "category": alert.get("category"),
        "action": alert.get("action", "allowed"),
        "raw_event_hash": event_hash,
    }


def process_line(line: str) -> bool:
    line = line.strip()
    if not line:
        return False
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return False

    normalized = normalize_event(event)
    if normalized is None:
        return False

    inserted = database.insert_alert(normalized)
    if inserted:
        print(
            f"[ALERT] {normalized['timestamp']} | "
            f"{normalized['src_ip']} -> {normalized['dest_ip']}:{normalized['dest_port']} | "
            f"{normalized['signature']} (severity={normalized['severity']})"
        )
        maybe_trigger_response(normalized)
    return inserted


def maybe_trigger_response(alert: dict):
    """
    Safe local response mechanism: for high/critical severity alerts (1 or 2),
    write an entry to response_log.txt. This NEVER touches a real firewall.
    """
    if alert.get("severity") not in (1, 2):
        return

    response_log_path = os.path.join(os.path.dirname(__file__), "..", "response_log.txt")
    severity_label = "CRITICAL" if alert["severity"] == 1 else "HIGH"
    entry = (
        f"[{alert['timestamp']}]\n"
        f"ALERT: {alert['signature']}\n"
        f"SOURCE: {alert['src_ip']}\n"
        f"SEVERITY: {severity_label}\n"
        f"ACTION: Logged and added to temporary lab blocklist (demonstration only)\n\n"
    )
    with open(response_log_path, "a") as f:
        f.write(entry)


def run_once(file_path: str):
    if not os.path.exists(file_path):
        print(f"[ERROR] eve.json not found at {file_path}. Has Suricata been started?")
        sys.exit(1)

    count = 0
    with open(file_path, "r") as f:
        for line in f:
            if process_line(line):
                count += 1
    print(f"[INFO] Parsed file once. {count} new alert(s) inserted.")


def run_watch(file_path: str, poll_interval: float = 1.0):
    print(f"[INFO] Watching {file_path} for new alerts... (Ctrl+C to stop)")
    # Wait for the file to exist (Suricata may not have started yet)
    while not os.path.exists(file_path):
        print("[INFO] Waiting for eve.json to be created by Suricata...")
        time.sleep(2)

    with open(file_path, "r") as f:
        f.seek(0, os.SEEK_END)  # start at the end; only process new lines
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            process_line(line)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse Suricata eve.json alerts into SQLite.")
    parser.add_argument("--file", default=DEFAULT_EVE_PATH, help="Path to eve.json")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true", help="Parse existing file once and exit")
    mode.add_argument("--watch", action="store_true", help="Continuously watch for new alerts")
    args = parser.parse_args()

    database.init_db()

    if args.once:
        run_once(args.file)
    else:
        run_watch(args.file)
