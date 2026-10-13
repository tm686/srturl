#!/usr/bin/env bash
# recon-runner bundle builder — RUNS ON YOUR HOST (unrestricted network).
# Downloads all binaries, templates, wordlists, and offline wheels,
# then zips them into recon-runner-bundle.zip for transfer to the VDI.
set -euo pipefail

OUTDIR="$(mktemp -d)"
BUNDLE_NAME="recon-runner-bundle.zip"
ARCH="linux_amd64"

echo "=== recon-runner bundle builder ==="
echo "[*] Staging in $OUTDIR"

mkdir -p "$OUTDIR"/{bin,nuclei-templates,wordlists,wheels,pysrc}

# --- Helper: download latest GitHub release binary ---
gh_release_bin() {
    local repo="$1" binary="$2" pattern="$3"
    echo "[*] Fetching $binary from $repo..."
    local url
    url=$(curl -sL "https://api.github.com/repos/$repo/releases/latest" \
        | grep -oP "\"browser_download_url\":\s*\"[^\"]*${pattern}[^\"]*\"" \
        | head -1 | grep -oP 'https://[^"]+') || true
    if [ -z "$url" ]; then
        echo "[!] Could not find release for $binary ($pattern)"
        return 1
    fi
    local tmp="$(mktemp)"
    curl -sL "$url" -o "$tmp"

    # Extract archive into a temp dir, then find the actual binary
    local extract_dir="$(mktemp -d)"
    case "$url" in
        *.zip)
            unzip -qo "$tmp" -d "$extract_dir" && rm "$tmp"
            ;;
        *.tar.gz|*.tgz)
            tar xzf "$tmp" -C "$extract_dir" && rm "$tmp"
            ;;
        *)
            mv "$tmp" "$OUTDIR/bin/$binary"
            chmod +x "$OUTDIR/bin/$binary" 2>/dev/null || true
            rm -rf "$extract_dir"
            return 0
            ;;
    esac

    # PD tools extract into nested dirs (e.g., subfinder_0.6.0_linux_amd64/subfinder)
    # Find the actual binary by name and move it
    local found
    found=$(find "$extract_dir" -type f -name "$binary" | head -1)
    if [ -n "$found" ]; then
        mv "$found" "$OUTDIR/bin/$binary"
    else
        # Fallback: look for any executable in extracted files
        found=$(find "$extract_dir" -type f -executable | head -1)
        if [ -n "$found" ]; then
            mv "$found" "$OUTDIR/bin/$binary"
        else
            echo "[!] No binary found after extracting $binary"
        fi
    fi
    chmod +x "$OUTDIR/bin/$binary" 2>/dev/null || true
    rm -rf "$extract_dir"
}

# --- ProjectDiscovery tools ---
gh_release_bin "projectdiscovery/subfinder"  subfinder  "${ARCH}"
gh_release_bin "projectdiscovery/httpx"      httpx      "${ARCH}"
gh_release_bin "projectdiscovery/nuclei"     nuclei     "${ARCH}"
gh_release_bin "projectdiscovery/katana"     katana     "${ARCH}"
gh_release_bin "projectdiscovery/naabu"      naabu      "${ARCH}"
gh_release_bin "projectdiscovery/dnsx"       dnsx       "${ARCH}"

# --- Other Go tools ---
gh_release_bin "ffuf/ffuf"                   ffuf       "${ARCH}"
gh_release_bin "hahwul/dalfox"               dalfox     "linux-x86_64" || true

# --- Go-install tools (no release binaries) ---
echo "[*] Building gau and waybackurls from source..."
if command -v go &>/dev/null; then
    GOBIN="$OUTDIR/bin" go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || \
        echo "[!] gau build failed"
    GOBIN="$OUTDIR/bin" go install github.com/tomnomnom/waybackurls@latest 2>/dev/null || \
        echo "[!] waybackurls build failed"
else
    echo "[!] Go not installed — skipping gau/waybackurls build"
fi

# --- Create httpx-toolkit alias ---
# tools.json uses binary_aliases: ["httpx-toolkit", "httpx"]
if [ -f "$OUTDIR/bin/httpx" ] && [ ! -f "$OUTDIR/bin/httpx-toolkit" ]; then
    cp "$OUTDIR/bin/httpx" "$OUTDIR/bin/httpx-toolkit"
    echo "[*] Created httpx-toolkit alias"
fi

# --- Nuclei templates ---
echo "[*] Downloading nuclei-templates..."
curl -sL "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip" \
    -o "$OUTDIR/nt.zip"
unzip -qo "$OUTDIR/nt.zip" -d "$OUTDIR/" && rm "$OUTDIR/nt.zip"
mv "$OUTDIR/nuclei-templates-main" "$OUTDIR/nuclei-templates"

# --- Wordlists ---
echo "[*] Downloading wordlists..."
SECLISTS_RAW="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
curl -sL "$SECLISTS_RAW/Discovery/Web-Content/raft-medium-directories.txt" \
    -o "$OUTDIR/wordlists/raft-medium-directories.txt"
curl -sL "$SECLISTS_RAW/Discovery/Web-Content/common.txt" \
    -o "$OUTDIR/wordlists/common.txt"
# DNS wordlist for R2 brute-force pipeline
curl -sL "$SECLISTS_RAW/Discovery/DNS/subdomains-top1million-5000.txt" \
    -o "$OUTDIR/wordlists/dns-subdomains.txt"
# Arjun's default params
curl -sL "https://raw.githubusercontent.com/s0md3v/Arjun/master/arjun/db/large.txt" \
    -o "$OUTDIR/wordlists/arjun-params.txt" 2>/dev/null || true

# --- Arjun offline wheels ---
echo "[*] Downloading arjun wheels for offline install..."
pip3 download arjun -d "$OUTDIR/wheels" --no-cache-dir 2>/dev/null || \
    echo "[!] pip download arjun failed"

# --- Arjun + sqlmap source ---
echo "[*] Downloading arjun source..."
git clone --depth 1 https://github.com/s0md3v/Arjun.git "$OUTDIR/pysrc/arjun" 2>/dev/null && \
    rm -rf "$OUTDIR/pysrc/arjun/.git" || echo "[!] arjun clone failed"

echo "[*] Downloading sqlmap source..."
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$OUTDIR/pysrc/sqlmap" 2>/dev/null && \
    rm -rf "$OUTDIR/pysrc/sqlmap/.git" || echo "[!] sqlmap clone failed"

# --- Summary ---
echo ""
echo "[*] Bundle contents:"
echo "    Binaries:"
for f in "$OUTDIR"/bin/*; do
    [ -f "$f" ] && echo "      $(basename "$f")"
done
echo "    Templates: $(find "$OUTDIR/nuclei-templates" -name "*.yaml" 2>/dev/null | wc -l) yaml files"
echo "    Wordlists: $(ls "$OUTDIR/wordlists/"*.txt 2>/dev/null | wc -l) files"

# --- Zip it up ---
echo ""
echo "[*] Creating $BUNDLE_NAME..."
cd "$OUTDIR" && zip -qr "$OLDPWD/$BUNDLE_NAME" . && cd "$OLDPWD"

# --- Cleanup ---
rm -rf "$OUTDIR"

SIZE=$(du -h "$BUNDLE_NAME" | cut -f1)
echo ""
echo "=== Bundle complete: $BUNDLE_NAME ($SIZE) ==="
echo "Transfer to VDI and run: bash install.sh"
