# Architecture — CodeAlpha Task 4 IDS

## Text Architecture Diagram

```
 ┌─────────────────────────┐
 │   Test Traffic           │  generate_test_traffic.py — SAFE, local-only,
 │   (127.0.0.1 only)        │  refuses any public IP target
 └────────────┬──────────────┘
              │
              ▼
 ┌─────────────────────────┐
 │  Network Interface (lo)  │  the loopback interface Suricata listens on
 └────────────┬──────────────┘
              │  raw packets captured via af-packet
              ▼
 ┌─────────────────────────┐
 │      Suricata Engine     │  inspects every packet/flow against loaded rules
 └────────────┬──────────────┘
              │  matched against
              ▼
 ┌─────────────────────────┐
 │  Detection Rules          │  rules/local.rules — 5 custom signatures
 │  (rules/local.rules)      │
 └────────────┬──────────────┘
              │  on match
              ▼
 ┌─────────────────────────┐
 │    Alert Generation       │  Suricata writes a structured alert event
 └────────────┬──────────────┘
              │
              ▼
 ┌─────────────────────────┐
 │ logs/eve.json (JSON)      │  machine-readable event log (used by parser)
 │ logs/fast.log (text)      │  human-readable one-line-per-alert log
 └────────────┬──────────────┘
              │  tailed/read by
              ▼
 ┌─────────────────────────┐
 │ Python Log Processor      │  scripts/parse_alerts.py — normalizes fields,
 │ (parse_alerts.py)         │  hashes events to avoid duplicates
 └────────────┬──────────────┘
              │  parameterized INSERT
              ▼
 ┌─────────────────────────┐
 │ SQLite Database            │  database/ids_alerts.db — indexed `alerts` table
 │ (ids_alerts.db)            │
 └────────────┬──────────────┘
              │  queried via Flask API routes
              ▼
 ┌─────────────────────────┐
 │ Local Web Dashboard        │  dashboard/app.py → http://127.0.0.1:5000
 │ (Flask + Chart.js)         │  local-only, never exposed publicly
 └─────────────────────────┘
```

## Component Explanations

### 1. Network Traffic
All traffic in this project is generated intentionally by `generate_test_traffic.py` against `127.0.0.1` (or another explicitly private lab address). No traffic is ever directed at systems outside the lab.

### 2. Suricata
Suricata is an open-source network IDS/IPS engine. In this project it runs in **IDS mode only** (detection, not prevention/blocking) — it observes traffic and raises alerts, but never drops or modifies packets.

### 3. Detection Engine & Rules
Suricata compares each packet/flow against the rules in `rules/local.rules`. Each rule specifies a protocol, source/destination, and a pattern to match (e.g. an ICMP echo request, a specific HTTP URI, a burst of SYN packets). See `docs/DETECTION_RULES.md` for full detail on each rule.

### 4. EVE JSON
Suricata's "Extensible Event Format" — a structured, line-delimited JSON log where every event (alert, HTTP, DNS, etc.) is one JSON object per line. This project only consumes `event_type: alert` entries.

### 5. Python Processor
`scripts/parse_alerts.py` reads `eve.json` (once, or continuously with `--watch`), extracts the fields we care about (timestamp, IPs, ports, protocol, signature, severity, category), computes a hash of each raw event to prevent duplicate inserts, and stores the result in SQLite via `scripts/database.py`.

### 6. SQLite Database
A single `alerts` table with indexes on timestamp, severity, source IP, and signature ID for fast dashboard queries. All access uses parameterized queries (see Security Considerations in the README).

### 7. Dashboard
A Flask app exposing JSON API routes (`/api/summary`, `/api/timeline`, `/api/top-sources`, `/api/top-ports`, `/api/top-signatures`, `/api/alerts`) consumed by a single-page frontend (`templates/index.html` + `static/dashboard.js`) using Chart.js for visualizations. Bound to `127.0.0.1` only.

### 8. Response Mechanism
When `parse_alerts.py` inserts a Critical or High severity alert, it also appends an entry to `response_log.txt` describing the detection and a (simulated/local-only) response action. No real firewall or network device is ever modified by this project.

## Windows Setup Option

Suricata does not run natively on Windows in a way that's ideal for this kind of lab. The simplest reliable path:

```
Windows Host
   │
   ▼
WSL2 (Windows Subsystem for Linux 2) — Ubuntu
   │
   ▼
Suricata installed inside WSL2 Ubuntu
   │
   ▼
Python scripts + Flask dashboard also run inside WSL2
```

To set up WSL2:
```powershell
wsl --install -d Ubuntu
```
Then follow the Linux installation steps in the main `README.md` inside the WSL2 Ubuntu terminal. The dashboard, once started inside WSL2, is reachable from the Windows browser at `http://127.0.0.1:5000` (WSL2 forwards localhost ports to Windows automatically).

An alternative (Option B) is running a full Ubuntu VM (VirtualBox/VMware) instead of WSL2 — more isolated, slightly more setup overhead, useful if you want a second VM as a distinct "attacker" lab machine instead of using loopback traffic.
