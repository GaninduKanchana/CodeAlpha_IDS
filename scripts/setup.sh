#!/bin/bash
# setup.sh — one-time project setup
# Run from the project root: ./scripts/setup.sh
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "[INFO] Creating runtime directories..."
mkdir -p logs database screenshots

echo "[INFO] Initializing SQLite database..."
python3 scripts/database.py

echo "[INFO] Checking Suricata installation..."
if command -v suricata >/dev/null 2>&1; then
    echo "[INFO] Suricata found: $(suricata --build-info | head -n 1)"
else
    echo "[WARN] Suricata not found. Install it with: sudo apt install suricata"
fi

echo "[PASS] Setup complete. Next: sudo ./scripts/start_ids.sh"
