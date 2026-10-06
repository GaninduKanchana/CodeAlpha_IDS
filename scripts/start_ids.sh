#!/bin/bash
# start_ids.sh — start Suricata in IDS (monitor-only) mode on the loopback
# interface, using this project's config and rules.
# Must be run with sudo (Suricata needs raw packet capture privileges).
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

INTERFACE="${1:-lo}"

echo "[INFO] Validating configuration..."
suricata -T -c config/suricata.yaml -l logs || {
    echo "[FAIL] Suricata configuration test failed. See errors above.";
    exit 1;
}

echo "[INFO] Starting Suricata on interface: $INTERFACE"
suricata -c config/suricata.yaml -i "$INTERFACE" -l logs -D

sleep 2
if pgrep -x suricata >/dev/null; then
    echo "[PASS] Suricata started successfully. Alerts logging to logs/eve.json"
else
    echo "[FAIL] Suricata did not start. Check logs/suricata.log for details."
    exit 1
fi
