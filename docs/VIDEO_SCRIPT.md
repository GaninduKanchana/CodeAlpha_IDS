# Demo Video Script — CodeAlpha Task 4 IDS

A suggested 4–6 minute walkthrough script for a submission video.

## 1. Intro (30s)
"Hi, I'm [name], and this is my Task 4 submission for the CodeAlpha Cyber Security Internship — a Network Intrusion Detection System built with Suricata, Python, and a local dashboard. Everything you'll see runs entirely inside my own local lab — I never send traffic to any system I don't own."

## 2. Architecture Overview (45s)
Show `docs/ARCHITECTURE.md` diagram. Walk through: test traffic → Suricata → rules → alerts → eve.json → Python parser → SQLite → dashboard.

## 3. Show the Custom Rules (45s)
Open `rules/local.rules`. Briefly explain 2–3 of the five rules (e.g. the ICMP rule and the failed-login rule), pointing out SID, message, and severity.

## 4. Start the IDS (30s)
Run `sudo ./scripts/start_ids.sh`, show the "Suricata started successfully" output.

## 5. Start the Processor and Dashboard (30s)
Run `parse_alerts.py --watch` and `dashboard/app.py`. Open `http://127.0.0.1:5000` in the browser, showing the empty/initial dashboard.

## 6. Generate Safe Test Traffic (60–90s)
Run `python3 scripts/generate_test_traffic.py --all`. Narrate each `[INFO]`/`[PASS]` line as it appears. Switch to the dashboard and refresh (or show auto-refresh) — point out the alert counts increasing, the timeline chart updating, and new rows appearing in the alerts table with severity badges.

## 7. Show Raw Logs (30s)
`cat logs/fast.log` and briefly show a snippet of `logs/eve.json` to demonstrate the underlying data the dashboard is built from.

## 8. Show the Response Log (20s)
`cat response_log.txt` — show that Critical/High alerts were logged with a local, safe response action.

## 9. Wrap-up (30s)
"That's a full detection pipeline — from safe test traffic, through Suricata detection and custom rules, to a live dashboard — all running locally. Full documentation, including the architecture, rule write-ups, and test plan, is in the project's `docs/` folder. Thanks for watching!"
