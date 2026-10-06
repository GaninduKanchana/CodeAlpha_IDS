# Detection Rules — CodeAlpha Task 4 IDS

All rules are defined in `rules/local.rules`. SIDs 1000001–1000005 (the 1,000,000+ range is the conventional space for local/custom Suricata rules).

---

## Rule 1 — ICMP Test Traffic

- **Rule ID:** RULE-01
- **SID:** 1000001
- **Name:** CODEALPHA TEST ICMP Probe Detected
- **Purpose:** Demonstrate basic protocol-level detection of ICMP echo requests (ping) — a common first step in reconnaissance.
- **Detection logic:** Matches any ICMP packet of type 8 (echo request) destined for `$HOME_NET`.
- **Severity:** Medium (3)
- **Safe test:** `python3 scripts/generate_test_traffic.py --icmp`
- **Expected alert:** `"CODEALPHA TEST ICMP Probe Detected"` in `logs/fast.log` / dashboard within a few seconds of running the test.
- **Interpretation:** A single ping is usually benign (e.g. connectivity checks) — in a real network this rule would typically be combined with a threshold (many pings in a short window) to reduce noise; here it's kept simple for demonstration.

---

## Rule 2 — Suspicious HTTP Request Pattern

- **Rule ID:** RULE-02
- **SID:** 1000002
- **Name:** CODEALPHA TEST Suspicious HTTP Request Pattern
- **Purpose:** Demonstrate application-layer (HTTP) content inspection — detecting a specific suspicious-looking URI.
- **Detection logic:** Matches an HTTP request to `$HOME_NET` whose URI contains `/codealpha-test-suspicious`.
- **Severity:** High (2)
- **Safe test:** `python3 scripts/generate_test_traffic.py --http`
- **Expected alert:** `"CODEALPHA TEST Suspicious HTTP Request Pattern"`.
- **Interpretation:** In a real scenario this pattern mimics detecting requests for known-malicious paths (e.g. webshell probes, `/etc/passwd` path traversal attempts) — here the "malicious" path is a made-up test string unique to this project.

---

## Rule 3 — Port Scanning Pattern

- **Rule ID:** RULE-03
- **SID:** 1000003
- **Name:** CODEALPHA TEST Possible Port Scan Detected
- **Purpose:** Demonstrate threshold-based detection of a burst of connection attempts — a classic port-scan indicator.
- **Detection logic:** Matches TCP SYN packets to `$HOME_NET`; fires once 10+ are seen from the same source within 5 seconds (`threshold: track by_src, count 10, seconds 5`).
- **Severity:** High (2)
- **Safe test:** `python3 scripts/generate_test_traffic.py --port-scan`
- **Expected alert:** `"CODEALPHA TEST Possible Port Scan Detected"`.
- **Interpretation:** Real port scanners (e.g. reconnaissance tools) probe many ports quickly; this rule's threshold approximates that behavior without needing a real scanning tool.

---

## Rule 4 — Suspicious Authentication Test Pattern

- **Rule ID:** RULE-04
- **SID:** 1000004
- **Name:** CODEALPHA TEST Repeated Failed Login Attempts
- **Purpose:** Demonstrate detection of brute-force-style repeated login attempts against a local test endpoint.
- **Detection logic:** Matches repeated `POST /codealpha-test-login` HTTP requests from the same source — 5+ within 10 seconds.
- **Severity:** Critical (1)
- **Safe test:** `python3 scripts/generate_test_traffic.py --login-test` (posts obviously-fake test credentials to a path our own script defines — no real service or real credentials involved).
- **Expected alert:** `"CODEALPHA TEST Repeated Failed Login Attempts"`.
- **Interpretation:** Mirrors detecting credential-stuffing/brute-force login attempts against a real login form; severity is set to Critical since repeated auth failures are high-signal in real environments.

---

## Rule 5 — Custom CodeAlpha Proof-of-Life Signature

- **Rule ID:** RULE-05
- **SID:** 1000005
- **Name:** CODEALPHA TEST Proof-of-Life Signature Triggered
- **Purpose:** A completely harmless, unique byte-string signature used purely to prove the full pipeline works end-to-end (traffic → Suricata → eve.json → parser → database → dashboard).
- **Detection logic:** Matches any TCP payload containing the literal string `CODEALPHA-IDS-TEST-SIGNATURE`.
- **Severity:** Low (4)
- **Safe test:** `python3 scripts/generate_test_traffic.py --signature`
- **Expected alert:** `"CODEALPHA TEST Proof-of-Life Signature Triggered"` should appear in the dashboard within seconds — the fastest way to confirm the whole system is wired up correctly.
- **Interpretation:** Not meant to represent a real-world threat — this is the project's own "hello world" / smoke test signature.

---

## Severity Scale Used in This Project

| Value | Meaning |
|---|---|
| 1 | Critical |
| 2 | High |
| 3 | Medium |
| 4 | Low |

These are **project-level demonstration categories**, not equivalent to CVSS scores or any industry-standard severity framework.
