#!/usr/bin/env bash
# recon-runner OFFLINE installer — runs on the VDI box.
# Expects recon-runner-bundle.zip alongside this script (built by bundle.sh).
# NO network access required.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

BUNDLE="recon-runner-bundle.zip"
BIN_INSTALL_DIR="/usr/local/bin"
LOCAL_BIN_DIR="./bin"
DATA_DIR="./data"

echo "=== recon-runner offline installer ==="

# --- Unzip bundle ---
if [ ! -f "$BUNDLE" ]; then
    echo "[!] $BUNDLE not found beside this script."
    echo "    Build it on your host with: bash bundle.sh"
    exit 1
fi

echo "[*] Extracting bundle..."
BUNDLE_TMP="$(mktemp -d)"
unzip -qo "$BUNDLE" -d "$BUNDLE_TMP"

# --- Install binaries ---
echo "[*] Installing binaries..."
if [ -w "$BIN_INSTALL_DIR" ] || sudo -n test -w "$BIN_INSTALL_DIR" 2>/dev/null; then
    DEST="$BIN_INSTALL_DIR"
    SUDO_CMD="sudo"
else
    DEST="$LOCAL_BIN_DIR"
    SUDO_CMD=""
    mkdir -p "$DEST"
    echo "[!] /usr/local/bin not writable, installing to $DEST"
fi

for bin in "$BUNDLE_TMP"/bin/*; do
    [ -f "$bin" ] || continue
    $SUDO_CMD cp "$bin" "$DEST/"
    $SUDO_CMD chmod +x "$DEST/$(basename "$bin")"
    echo "    $(basename "$bin") -> $DEST/"
done

# --- Copy templates, wordlists, pysrc ---
echo "[*] Installing data files..."
mkdir -p "$DATA_DIR"
[ -d "$BUNDLE_TMP/nuclei-templates" ] && cp -r "$BUNDLE_TMP/nuclei-templates" "$DATA_DIR/"
[ -d "$BUNDLE_TMP/wordlists" ]        && cp -r "$BUNDLE_TMP/wordlists" "$DATA_DIR/"
[ -d "$BUNDLE_TMP/pysrc" ]            && cp -r "$BUNDLE_TMP/pysrc" "$DATA_DIR/"

# --- Install arjun from offline wheels if pip exists ---
if [ -d "$BUNDLE_TMP/wheels" ]; then
    if command -v pip3 &>/dev/null; then
        echo "[*] Installing arjun from offline wheels..."
        pip3 install --no-index --find-links "$BUNDLE_TMP/wheels" arjun 2>/dev/null || \
            echo "[!] pip install failed; wrapping arjun source instead"
    fi
    if ! command -v arjun &>/dev/null && [ -d "$DATA_DIR/pysrc/arjun" ]; then
        echo "[*] Wrapping arjun source..."
        cat > "$DEST/arjun" << 'ARJUN_WRAP'
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 -m arjun "$@"
ARJUN_WRAP
        chmod +x "$DEST/arjun"
        export PYTHONPATH="$DATA_DIR/pysrc:${PYTHONPATH:-}"
    fi
fi

# --- Wrap sqlmap source ---
if [ -d "$DATA_DIR/pysrc/sqlmap" ] && ! command -v sqlmap &>/dev/null; then
    echo "[*] Wrapping sqlmap source..."
    cat > "$DEST/sqlmap" << SQLMAP_WRAP
#!/usr/bin/env bash
exec python3 "$SCRIPT_DIR/$DATA_DIR/pysrc/sqlmap/sqlmap.py" "\$@"
SQLMAP_WRAP
    chmod +x "$DEST/sqlmap"
fi

# --- Write paths.json ---
echo "[*] Writing config/paths.json..."
REAL_DEST="$(cd "$DEST" && pwd)"
cat > config/paths.json << PATHSJSON
{
  "bin_dir": "$REAL_DEST",
  "nuclei_templates": "$SCRIPT_DIR/$DATA_DIR/nuclei-templates",
  "wordlists_dir": "$SCRIPT_DIR/$DATA_DIR/wordlists",
  "screenshots_dir": "$SCRIPT_DIR/$DATA_DIR/screenshots",
  "db_path": "$SCRIPT_DIR/$DATA_DIR/recon.db"
}
PATHSJSON

mkdir -p "$DATA_DIR/screenshots"

# --- Cleanup ---
rm -rf "$BUNDLE_TMP"

# --- Run doctor ---
echo ""
echo "=== Running preflight checks ==="
python3 doctor.py || echo "[!] Some checks failed — see above"

echo ""
echo "=== Install complete ==="
echo "Start with: bash run.sh"
