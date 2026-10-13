#!/usr/bin/env bash
# recon-runner OFFLINE installer — runs on the VDI box.
# Expects recon-runner-bundle.zip alongside this script (built by bundle.sh).
# NO network access required.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

BUNDLE="recon-runner-bundle.zip"
BIN_INSTALL_DIR="/usr/local/bin"
LOCAL_BIN_DIR="$SCRIPT_DIR/bin"
DATA_DIR="$SCRIPT_DIR/data"

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

INSTALLED=0
for bin in "$BUNDLE_TMP"/bin/*; do
    [ -f "$bin" ] || continue
    $SUDO_CMD cp "$bin" "$DEST/"
    $SUDO_CMD chmod +x "$DEST/$(basename "$bin")"
    echo "    $(basename "$bin") -> $DEST/"
    INSTALLED=$((INSTALLED + 1))
done
echo "    $INSTALLED binaries installed"

# --- Ensure httpx-toolkit alias exists ---
if [ -f "$DEST/httpx" ] && [ ! -f "$DEST/httpx-toolkit" ]; then
    $SUDO_CMD cp "$DEST/httpx" "$DEST/httpx-toolkit"
    echo "    httpx-toolkit alias created"
fi

# --- Copy templates, wordlists, pysrc ---
echo "[*] Installing data files..."
mkdir -p "$DATA_DIR"
if [ -d "$BUNDLE_TMP/nuclei-templates" ]; then
    cp -r "$BUNDLE_TMP/nuclei-templates" "$DATA_DIR/"
    TMPL_COUNT=$(find "$DATA_DIR/nuclei-templates" -name "*.yaml" | wc -l)
    echo "    nuclei-templates: $TMPL_COUNT templates"
fi
if [ -d "$BUNDLE_TMP/wordlists" ]; then
    cp -r "$BUNDLE_TMP/wordlists" "$DATA_DIR/"
    WL_COUNT=$(ls "$DATA_DIR/wordlists/"*.txt 2>/dev/null | wc -l)
    echo "    wordlists: $WL_COUNT files"
fi
if [ -d "$BUNDLE_TMP/pysrc" ]; then
    cp -r "$BUNDLE_TMP/pysrc" "$DATA_DIR/"
    echo "    pysrc: arjun + sqlmap source"
fi

# --- Install arjun from offline wheels if pip exists ---
if [ -d "$BUNDLE_TMP/wheels" ]; then
    if command -v pip3 &>/dev/null; then
        echo "[*] Installing arjun from offline wheels..."
        pip3 install --no-index --find-links "$BUNDLE_TMP/wheels" arjun 2>/dev/null || \
            echo "[!] pip install failed; wrapping arjun source instead"
    fi
    if ! command -v arjun &>/dev/null && [ -d "$DATA_DIR/pysrc/arjun" ]; then
        echo "[*] Wrapping arjun source..."
        ARJUN_SRC="$DATA_DIR/pysrc/arjun"
        cat > "$DEST/arjun" << ARJUN_WRAP
#!/usr/bin/env bash
export PYTHONPATH="$ARJUN_SRC:\${PYTHONPATH:-}"
exec python3 -m arjun "\$@"
ARJUN_WRAP
        $SUDO_CMD chmod +x "$DEST/arjun"
    fi
fi

# --- Wrap sqlmap source ---
if [ -d "$DATA_DIR/pysrc/sqlmap" ] && ! command -v sqlmap &>/dev/null; then
    echo "[*] Wrapping sqlmap source..."
    cat > "$DEST/sqlmap" << SQLMAP_WRAP
#!/usr/bin/env bash
exec python3 "$DATA_DIR/pysrc/sqlmap/sqlmap.py" "\$@"
SQLMAP_WRAP
    $SUDO_CMD chmod +x "$DEST/sqlmap"
fi

# --- Write paths.json ---
echo "[*] Writing config/paths.json..."
REAL_DEST="$(cd "$DEST" && pwd)"
cat > config/paths.json << PATHSJSON
{
  "bin_dir": "$REAL_DEST",
  "nuclei_templates": "$DATA_DIR/nuclei-templates",
  "wordlists_dir": "$DATA_DIR/wordlists",
  "dns_wordlist": "$DATA_DIR/wordlists/dns-subdomains.txt",
  "screenshots_dir": "$DATA_DIR/screenshots",
  "db_path": "$DATA_DIR/recon.db"
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
