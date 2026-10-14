#!/usr/bin/env bash
# recon-runner launcher
# Prepends paths.json bin_dir to PATH, then starts the server.
# Usage: bash run.sh [--daemon] [--port PORT]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PORT=8777
DAEMON=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --daemon|-d) DAEMON=true; shift ;;
        --port|-p)
            if [[ $# -lt 2 ]]; then
                echo "[!] --port requires an argument"; exit 1
            fi
            PORT="$2"; shift 2 ;;
        *)           echo "Usage: bash run.sh [--daemon] [--port PORT]"; exit 1 ;;
    esac
done

PATHS_JSON="config/paths.json"

if [ -f "$PATHS_JSON" ]; then
    BIN_DIR=$(python3 -c "import json; print(json.load(open('$PATHS_JSON'))['bin_dir'])" 2>/dev/null || true)
    if [ -n "$BIN_DIR" ] && [ -d "$BIN_DIR" ]; then
        export PATH="$BIN_DIR:$PATH"
        echo "[*] Prepended $BIN_DIR to PATH"
    fi
else
    echo "[!] $PATHS_JSON not found — run install.sh first, or the server will"
    echo "    look for tools on the default PATH."
fi

echo "[*] Starting recon-runner on 127.0.0.1:$PORT"
echo "[*] Open http://127.0.0.1:$PORT in your browser"

if [ "$DAEMON" = true ]; then
    nohup python3 server.py --host 127.0.0.1 --port "$PORT" > "$SCRIPT_DIR/data/server.log" 2>&1 &
    echo "[*] Running in background (PID $!)"
    echo "[*] Logs: $SCRIPT_DIR/data/server.log"
    echo "[*] Stop: kill $!"
else
    exec python3 server.py --host 127.0.0.1 --port "$PORT"
fi
