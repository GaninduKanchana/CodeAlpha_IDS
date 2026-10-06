#!/bin/bash
# stop_ids.sh — stop the running Suricata process started by start_ids.sh
if pgrep -x suricata >/dev/null; then
    sudo pkill -x suricata
    echo "[INFO] Suricata stopped."
else
    echo "[INFO] Suricata was not running."
fi
