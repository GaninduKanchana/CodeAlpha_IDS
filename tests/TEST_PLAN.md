# Test Plan — CodeAlpha Task 4 IDS

All tests are run against `127.0.0.1` only, using `scripts/generate_test_traffic.py`. Fill in "Actual Result" and "Pass/Fail" after running each test with Suricata and the dashboard active.

| Test ID | Objective | Command | Expected Result | Actual Result | Pass/Fail | Screenshot |
|---|---|---|---|---|---|---|
| TEST-01 | Confirm normal traffic produces no malicious alert | `ping -c 2 127.0.0.1` (no test flags) | No CodeAlpha alert generated | | | `screenshots/test01.png` |
| TEST-02 | ICMP rule detection | `python3 scripts/generate_test_traffic.py --icmp` | Alert: "CODEALPHA TEST ICMP Probe Detected" (SID 1000001) in `logs/fast.log` and dashboard | | | `screenshots/test02.png` |
| TEST-03 | HTTP suspicious-pattern detection | `python3 scripts/generate_test_traffic.py --http` | Alert: "CODEALPHA TEST Suspicious HTTP Request Pattern" (SID 1000002) | | | `screenshots/test03.png` |
| TEST-04 | Port-scan pattern detection | `python3 scripts/generate_test_traffic.py --port-scan` | Alert: "CODEALPHA TEST Possible Port Scan Detected" (SID 1000003) | | | `screenshots/test04.png` |
| TEST-05 | Failed-login pattern detection | `python3 scripts/generate_test_traffic.py --login-test` | Alert: "CODEALPHA TEST Repeated Failed Login Attempts" (SID 1000004) | | | `screenshots/test05.png` |
| TEST-06 | Unrelated/invalid traffic does not falsely trigger custom rules | Browse to any unrelated local page, e.g. `curl http://127.0.0.1:8080/` | No CodeAlpha custom-rule alert (only generic traffic, if any) | | | `screenshots/test06.png` |
| TEST-07 | End-to-end pipeline proof (signature) | `python3 scripts/generate_test_traffic.py --signature` | Alert: "CODEALPHA TEST Proof-of-Life Signature Triggered" (SID 1000005) appears in dashboard within seconds | | | `screenshots/test07.png` |

## How to run a full pass

```bash
sudo ./scripts/start_ids.sh
source venv/bin/activate
python3 scripts/parse_alerts.py --watch &
python3 dashboard/app.py &
python3 scripts/generate_test_traffic.py --all
```
Then open `http://127.0.0.1:5000`, confirm each expected alert appears, screenshot the dashboard and `logs/fast.log`, and fill in the table above.
