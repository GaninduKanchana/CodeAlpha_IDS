# Project Report: Network Intrusion Detection System
### CodeAlpha Cyber Security Internship — Task 4

---

## 1. Introduction

This report documents the design, implementation, and testing of a Network Intrusion Detection System (IDS) built for Task 4 of the CodeAlpha Cyber Security Internship. The system uses Suricata as its detection engine, Python for log processing and safe test-traffic generation, SQLite for alert storage, and a local Flask-based dashboard for visualization.

## 2. Problem Statement

Organizations need visibility into their network traffic to detect suspicious or malicious activity before it causes damage. An Intrusion Detection System passively monitors traffic and raises alerts when known-bad or anomalous patterns are observed, without necessarily blocking the traffic itself (that would be an Intrusion *Prevention* System, or IPS).

This project implements a small-scale, educational IDS that demonstrates the full pipeline — from packet capture to rule matching, alerting, storage, and visualization — entirely within a safe, self-contained local lab.

## 3. Objectives

1. Set up Suricata as a network-based IDS.
2. Write custom detection rules for several traffic patterns.
3. Continuously monitor traffic and generate structured alerts.
4. Process and store alerts for analysis.
5. Visualize alerts on a dashboard.
6. Implement a safe, local response-logging mechanism.
7. Prove detection works via safe, self-generated test traffic.
8. Document the system thoroughly.

## 4. Background

**IDS vs IPS:** An IDS observes and alerts; an IPS can additionally block traffic inline. This project is strictly an IDS — it never modifies or blocks network traffic.

**Suricata:** An open-source, high-performance network threat detection engine capable of intrusion detection, inline intrusion prevention, network security monitoring, and offline pcap processing. It uses a rule language similar to Snort's.

**Signature-based detection:** Suricata (in this project) primarily uses signature/rule-based detection — matching traffic against known patterns — as opposed to purely statistical/anomaly-based detection.

## 5. IDS Architecture

See `docs/ARCHITECTURE.md` for the full diagram and component breakdown. In summary: test traffic → network interface → Suricata → custom rules → alert → `eve.json`/`fast.log` → Python processor → SQLite → dashboard.

## 6. Technologies Used

- Suricata (IDS engine)
- Python 3 (log parsing, database layer, test traffic generator)
- SQLite (alert storage)
- Flask (dashboard backend/API)
- HTML/CSS/JavaScript + Chart.js (dashboard frontend)
- Git (version control)

## 7. Installation

See the "Installation" section of the main `README.md` for exact, step-by-step commands (Suricata install, Python virtual environment, dependency installation, project setup script).

## 8. Configuration

`config/suricata.yaml` defines `HOME_NET`/`EXTERNAL_NET`, the custom rule path, EVE JSON and fast-log outputs, and the capture interface (loopback, for this lab). Every setting is explained inline via comments in the file itself.

## 9. Detection Rules

Five custom rules were written (see `docs/DETECTION_RULES.md` for full detail on each):

1. ICMP Test Traffic (SID 1000001, Medium)
2. Suspicious HTTP Request Pattern (SID 1000002, High)
3. Port Scanning Pattern (SID 1000003, High)
4. Suspicious Authentication Test Pattern (SID 1000004, Critical)
5. Custom CodeAlpha Proof-of-Life Signature (SID 1000005, Low)

## 10. Alert Generation

When Suricata matches a rule against observed traffic, it writes a structured alert event to `logs/eve.json` (JSON) and a summary line to `logs/fast.log` (plain text), including timestamp, source/destination IP and port, protocol, matched signature, SID, severity, and category.

## 11. Alert Processing

`scripts/parse_alerts.py` reads `eve.json`, filters for `event_type: alert` entries, normalizes the relevant fields, computes a SHA-256 hash of each raw event to prevent duplicate inserts, and writes the result into SQLite via parameterized `INSERT OR IGNORE` statements. It can run once (`--once`) or continuously tail the log (`--watch`).

## 12. Database

A single `alerts` table (see `scripts/database.py`) stores normalized alert data with indexes on `timestamp`, `severity`, `src_ip`, and `signature_id` for fast dashboard queries. All reads and writes use parameterized SQL — no string-built queries.

## 13. Dashboard

A Flask application (`dashboard/app.py`) exposes JSON API endpoints consumed by a single-page dashboard (`dashboard/templates/index.html`, `dashboard/static/`). It displays total/critical/high/medium/low counts, an alerts-over-time line chart, top source IPs and destination ports (bar charts), most-triggered signatures, and a searchable/filterable recent-alerts table with color-coded severity badges. It binds to `127.0.0.1` only.

## 14. Response Mechanism

For Critical/High severity alerts, `parse_alerts.py` appends a plain-text entry to `response_log.txt` documenting the detection and a simulated local response action (e.g. "added to temporary lab blocklist"). This project deliberately does **not** modify any real firewall or block real traffic — see Section 18 (Security Considerations) for the reasoning.

The distinction between the five stages is:
- **Detection** — recognizing a pattern in traffic (the Suricata rule match)
- **Alerting** — producing a structured record of that match (`eve.json`/`fast.log`)
- **Logging** — persisting that record for later analysis (SQLite)
- **Response** — taking (or recording) an action based on the alert (`response_log.txt`)
- **Prevention** — actively blocking the traffic (explicitly out of scope / disabled in this project)

## 15. Testing

Seven test cases are defined in `tests/TEST_PLAN.md`, covering: a normal-traffic baseline (no false alert), each of the five custom rules individually, and an unrelated-traffic check. Each test records objective, command, expected result, actual result, pass/fail, and a screenshot reference.

## 16. Results

*(To be filled in after running the tests in your lab environment — record actual results in `docs/TEST_RESULTS.md` and attach screenshots per `screenshots/README.md`.)*

## 17. False Positives

See the "False Positives" discussion below and in the README. Example: a legitimate diagnostic ping sweep by a network administrator would trigger Rule 1 (ICMP) exactly like our test traffic does — the rule cannot distinguish "friendly" ICMP from "hostile" ICMP by protocol alone, which is why real-world deployments tune rules with allow-lists, thresholds, and context (e.g. combining with other signals) rather than relying on any single rule in isolation. Detection systems require ongoing monitoring and tuning, and an IDS should never auto-block on a single low-confidence signal.

## 18. Security Considerations

- No hard-coded passwords or API keys anywhere in the codebase.
- Dashboard binds to `127.0.0.1` only — never exposed to a LAN or the internet by default.
- All SQLite access uses parameterized queries.
- User-supplied input (dashboard search/filter) is passed only as bound query parameters, never concatenated into SQL.
- The dashboard accepts no file uploads.
- Logs never contain real credentials — the login-test traffic uses obviously fake, script-defined test values.
- `generate_test_traffic.py` validates every target IP and refuses to run against any address that isn't loopback or private (RFC1918) — it is structurally incapable of targeting a public system.
- The response mechanism only ever writes to a local text file; it does not call any firewall API or modify system network rules.

## 19. Limitations

- Educational scope: not tuned or load-tested for production traffic volumes.
- Detection rules are narrowly scoped to this project's own safe test traffic, not a general threat feed.
- No claim of "enterprise-grade" or guaranteed real-world attack coverage is made.
- Dashboard has no authentication — acceptable only because it is local-only by design.

## 20. Future Improvements

- Map additional rules to MITRE ATT&CK techniques.
- Add optional, opt-in email/webhook notifications for Critical alerts.
- Add dashboard authentication if ever deployed beyond localhost.
- Add automated regression tests that replay sample `.pcap` files through Suricata in CI.
- Expand severity handling with configurable thresholds per rule.

## 21. Conclusion

This project demonstrates a complete, working, end-to-end Network Intrusion Detection System pipeline — from safe local traffic generation through Suricata detection, structured logging, normalized storage, and dashboard visualization — while keeping every component (target selection, response actions, data handling) strictly scoped to a controlled, self-owned lab environment.
