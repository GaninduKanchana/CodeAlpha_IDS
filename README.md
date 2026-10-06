# CodeAlpha Task 4 — Network Intrusion Detection System

A safe, educational Network Intrusion Detection System (IDS) built with **Suricata**, **Python**, and a local **Flask dashboard**. This project was built for the **CodeAlpha Cyber Security Internship (Task 4)**.

> ⚠️ **Scope & Safety**: This project is designed to run entirely inside a controlled local lab (localhost / a VM you own). It is **not** designed to attack, scan, or monitor any system you do not own or have explicit authorization to test. The included test-traffic generator refuses to target public IP addresses.

---

## Overview

The system captures network traffic on a local interface, inspects it against a set of custom Suricata detection rules, and raises alerts when suspicious patterns are seen. Alerts are written to `eve.json`, parsed by a Python script into a normalized SQLite database, and displayed on a local web dashboard with counts, charts, and a searchable alert table. A lightweight, safe "response" mechanism logs high-severity events and can optionally add a source IP to a **local, temporary** blocklist file (never a real firewall, unless explicitly enabled).

## Objectives

1. Monitor network traffic in a local lab environment.
2. Detect predefined suspicious patterns using Suricata rules.
3. Generate, log, and categorize alerts by severity.
4. Provide a simple way to inspect detected events (CLI + dashboard).
5. Safely generate test traffic against localhost only.
6. Produce evidence (logs, screenshots, test results) that detection works.
7. Document the system thoroughly for submission.

## Features

- Custom Suricata rule set (5 rules) covering ICMP probes, suspicious HTTP requests, port-scan-like behavior, brute-force login attempts, and a unique "proof-of-life" test signature.
- Python alert parser that reads `eve.json` (Suricata's structured JSON log) and stores normalized alerts in SQLite using parameterized queries.
- Flask dashboard (`http://127.0.0.1:5000`, local-only by default) showing:
  - Total / Critical / High / Medium / Low alert counts
  - Alerts-over-time chart
  - Top source IPs and destination ports
  - Most-triggered signatures
  - Searchable, filterable recent-alerts table with severity badges
  - Manual refresh + auto-refresh toggle
- Safe test-traffic generator (`generate_test_traffic.py`) that only targets `127.0.0.1` or an explicitly configured private lab IP, and rejects public IPs outright.
- Safe local response logging (`response_log.txt`) — no automatic firewall changes.
- Full documentation set for internship submission (`docs/`).

## Architecture

```
 Test Traffic (generate_test_traffic.py)
            │
            ▼
   Network Interface (lo / eth0 in lab)
            │
            ▼
      Suricata IDS Engine
            │  matches against
            ▼
   Custom Detection Rules (rules/local.rules)
            │
            ▼
      Alert Generation
            │
            ▼
   logs/eve.json + logs/fast.log
            │
            ▼
  Python Log Processor (scripts/parse_alerts.py)
            │
            ▼
   SQLite Database (database/ids_alerts.db)
            │
            ▼
  Local Web Dashboard (dashboard/app.py → 127.0.0.1:5000)
```

See `docs/ARCHITECTURE.md` for a component-by-component explanation.

## Technologies

- **Suricata** — network IDS engine
- **Python 3** — log parsing, database layer, test-traffic generation
- **SQLite** — normalized alert storage
- **Flask** — local dashboard backend
- **HTML / CSS / JavaScript (Chart.js)** — dashboard frontend
- **Git/GitHub** — version control

## Project Structure

```
CodeAlpha_Task4_IDS/
├── README.md
├── requirements.txt
├── .gitignore
├── config/
│   └── suricata.yaml
├── rules/
│   └── local.rules
├── scripts/
│   ├── setup.sh
│   ├── start_ids.sh
│   ├── stop_ids.sh
│   ├── parse_alerts.py
│   ├── database.py
│   └── generate_test_traffic.py
├── dashboard/
│   ├── app.py
│   ├── templates/index.html
│   └── static/{style.css, dashboard.js}
├── database/ids_alerts.db          (created at runtime)
├── logs/{eve.json, fast.log}       (created at runtime)
├── screenshots/README.md
├── tests/TEST_PLAN.md
└── docs/
    ├── PROJECT_REPORT.md
    ├── ARCHITECTURE.md
    ├── DETECTION_RULES.md
    ├── TEST_RESULTS.md
    └── VIDEO_SCRIPT.md
```

## Installation

This project assumes a **Debian/Ubuntu-based Linux environment** (native Ubuntu, a VM, or **WSL2** on Windows — WSL2 is the simplest path for Windows users, see `docs/ARCHITECTURE.md` → "Windows Setup Option").

### 1. Install Suricata

```bash
sudo apt update
sudo apt install -y suricata
```
- **Where to run it:** in your Linux terminal (native Linux, VM, or WSL2 Ubuntu).
- **What it does:** installs the Suricata IDS engine and a default config at `/etc/suricata/suricata.yaml`.
- **Expected output:** package install logs ending without errors; `suricata --build-info` should print version info afterward.
- **If it fails:** run `sudo apt update` again, check your internet connection, and confirm you're on Ubuntu 20.04+ (`lsb_release -a`).

### 2. Clone/copy this project

Copy `CodeAlpha_Task4_IDS/` into your Linux environment, e.g. `~/CodeAlpha_Task4_IDS`.

### 3. Install Python dependencies

```bash
cd ~/CodeAlpha_Task4_IDS
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
- **What it does:** creates an isolated Python environment and installs Flask and helper libraries.
- **Expected output:** "Successfully installed Flask ..." with no red error text.
- **If it fails:** ensure `python3-venv` is installed: `sudo apt install python3-venv`.

### 4. Run the setup script

```bash
chmod +x scripts/*.sh
./scripts/setup.sh
```
This copies the custom rule file and config into place and initializes the SQLite database (see script for exact steps and comments).

## Configuration

See `config/suricata.yaml` — a heavily commented configuration snippet covering `HOME_NET`, `EXTERNAL_NET`, rule paths, and EVE JSON / fast.log output. Full explanation in the "SURICATA CONFIGURATION" section of `docs/PROJECT_REPORT.md`.

## Custom Rules

Five custom rules live in `rules/local.rules`. Full write-up of each rule (purpose, SID, severity, safe test method, expected alert) is in `docs/DETECTION_RULES.md`.

## Running Suricata

```bash
sudo ./scripts/start_ids.sh
```
- **Where:** Linux terminal, from the project root.
- **What it does:** starts Suricata in IDS (monitor) mode on your loopback/lab interface, writing alerts to `logs/eve.json` and `logs/fast.log`.
- **Expected output:** "Suricata started successfully. Alerts logging to logs/eve.json".
- **If it fails:** check `sudo suricata -T -c config/suricata.yaml -i lo` (test mode) for a configuration error message, and confirm the interface name with `ip a`.

Stop it with:
```bash
sudo ./scripts/stop_ids.sh
```

## Running the Alert Processor

```bash
source venv/bin/activate
python3 scripts/parse_alerts.py
```
Reads new lines from `logs/eve.json`, normalizes each `alert` event, and inserts it into `database/ids_alerts.db`. Run this continuously (`--watch`) or once (`--once`) — see `--help`.

## Running the Dashboard

```bash
source venv/bin/activate
python3 dashboard/app.py
```
Then open **http://127.0.0.1:5000** in your browser. The dashboard binds to `127.0.0.1` only — it is never exposed to the network by default.

## Generating Safe Test Traffic

```bash
python3 scripts/generate_test_traffic.py --all
```
Or run individual modes: `--icmp`, `--http`, `--port-scan`, `--login-test`, `--signature`. The script only targets `127.0.0.1` (or a `--target` you explicitly pass) and **rejects any public IP address**.

## Testing

Full test plan with 6 test cases (expected vs. actual results, pass/fail, screenshot requirements) is in `tests/TEST_PLAN.md`, with recorded results in `docs/TEST_RESULTS.md`.

## Sample Alerts

Example `eve.json` alert (from a safe local test):
```json
{"timestamp":"2026-01-01T10:00:00.000000+0000","event_type":"alert","src_ip":"127.0.0.1","src_port":0,"dest_ip":"127.0.0.1","dest_port":0,"proto":"ICMP","alert":{"signature":"CODEALPHA TEST ICMP Probe Detected","signature_id":1000001,"severity":3,"category":"Attempted Information Leak"}}
```

## Screenshots

Add screenshots of Suricata running, dashboard views, and alert logs to `screenshots/` (see `screenshots/README.md` for the checklist).

## Security Considerations

- No hard-coded passwords or API keys anywhere in this project.
- Dashboard listens on `127.0.0.1` only by default — not exposed to the LAN/internet.
- All SQLite queries use parameterized statements (no string-concatenated SQL).
- The test-traffic generator validates and rejects public/non-private IP targets before sending anything.
- No file uploads are accepted by the dashboard.
- Logs do not store credentials; the login-test rule/traffic uses obviously fake, local-only test credentials against a script you control.
- Optional firewall/blocklist integration is disabled by default and clearly labeled demonstration-only.

## Limitations

- This is a learning project, not a production security appliance — it has not been hardened or performance-tuned for real network traffic volumes.
- Detection rules are intentionally simple and specific to the safe test traffic generated by this project; they are not a general-purpose threat feed.
- No claim of "enterprise-grade" security or guaranteed detection of real-world attacks is made.

## Future Improvements

- Add more MITRE ATT&CK-mapped rules.
- Add email/webhook alerting for high-severity events (opt-in).
- Add user authentication to the dashboard if ever run beyond localhost.
- Add automated CI tests that replay sample pcaps through Suricata.

## Author

CodeAlpha Cyber Security Internship — Task 4 submission.
