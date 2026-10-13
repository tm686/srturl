#!/usr/bin/env bash
# recon-runner launcher
# Prepends paths.json bin_dir to PATH, then starts the server.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PATHS_JSON="config/paths.json"

if [ -f "$PATHS_JSON" ]; then
    BIN_DIR=$(python3 -c "import json; print(json.load(open('$PATHS_JSON'))['bin_dir'])" 2>/dev/null || true)
    if [ -n "$BIN_DIR" ] && [ -d "$BIN_DIR" ]; then
        export PATH="$BIN_DIR:$PATH"
        echo "[*] Prepended $BIN_DIR to PATH"
    fi
else
    echo "[!] $PATHS_JSON not found — run install.sh first"
fi

echo "[*] Starting recon-runner on 127.0.0.1:8777"
exec python3 server.py --host 127.0.0.1 --port 8777
