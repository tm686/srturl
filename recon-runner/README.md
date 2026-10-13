# recon-runner

Local recon & testing orchestrator for authorized Synack Red Team engagements.
Pure Python 3 stdlib. Inspired by [ars0n-framework-v2](https://github.com/R-s0n/ars0n-framework-v2).

## Architecture

- **Orchestration only** — wraps standard recon/testing CLI binaries behind a
  localhost-only web UI, runs them in a proven order, throttles for non-disruptive
  testing, consolidates output for lead prioritization.
- **No novel scanning logic.** No third-party Python packages.
- **Offline-capable** — designed for locked-down VDI environments where TLS
  inspection breaks package managers.

## Install flow

Source code and binaries are split by size:

| What | Where | How |
|------|-------|-----|
| Source code (this repo) | GitHub | `git clone` or download ZIP via browser |
| Tool binaries + nuclei-templates + wordlists | Offline bundle | Built by `bundle.sh` on your host |

### 1. Build the bundle (on your HOST — unrestricted network)

```bash
git clone https://github.com/tm686/srturl.git
cd srturl/recon-runner
bash bundle.sh
# produces: recon-runner-bundle.zip
```

Requires: `curl`, `unzip`, `git`. Optional: `go` (for gau/waybackurls), `pip3` (for arjun wheels).

### 2. Transfer to the VDI

Copy both the repo (or ZIP) and `recon-runner-bundle.zip` to the VDI box.

**Kali WSL note:** Copy the zip off `/mnt/c` into `~` before installing.
Running from `/mnt/c` causes permission and performance issues.

```bash
cp /mnt/c/Users/you/Downloads/recon-runner-bundle.zip ~/recon-runner/
```

### 3. Install (on the VDI — offline)

```bash
cd ~/recon-runner
bash install.sh
```

This will:
- Extract binaries to `/usr/local/bin` (or `./bin` if not writable)
- Create `httpx-toolkit` alias for httpx compatibility
- Copy nuclei-templates and wordlists to `./data/`
- Install arjun from offline wheels (or wrap source)
- Wrap sqlmap source
- Write `config/paths.json` with absolute paths
- Run `doctor.py` preflight checks

### 4. Run

```bash
bash run.sh
# Open http://127.0.0.1:8777
```

Options:
- `--daemon` / `-d` — run in background, log to `data/server.log`
- `--port PORT` / `-p PORT` — bind to a different port (default: 8777)

## Configuration

All tunables live in `config/*.json`:

- **tools.json** — tool registry (binaries, flags, phases, templates, binary_aliases)
- **profiles.json** — throttle profiles (stealth/slow/normal/fast)
- **roi.json** — ROI scoring weights for wildcard report
- **scope.json** — allowed domains/IPs (populate per engagement)
- **paths.json** — tool/data paths (written by install.sh)

## Workflows

### Wildcard (*.domain.com)
Three-round recon with consolidation between each:
1. **Passive:** subfinder -> dnsx -> httpx
2. **DNS:** brute/perms -> dnsx -> httpx
3. **Crawl:** katana -> consolidate new hosts -> httpx

Then: screenshots, metadata, ROI scoring, ranked report.

### URL (single target)
Promoted from wildcard report or added directly:
1. **U1 — Collect + Crawl:** gau + waybackurls -> katana
2. **U2 — Params + Fuzz:** arjun -> ffuf
3. **U3 — Attack:** dalfox + nuclei (sqlmap gated, disabled by default)

Attack phase requires explicit confirmation in the UI.

### Evidence export
Findings store request/response evidence for triage. Export from the UI or API:
- **JSON:** `GET /api/export/json` — full bundle (findings, URLs, params, scans)
- **CSV:** `GET /api/export/csv` — tabular format for spreadsheet review

## Scope safety

- `config/scope.json` defines allowed targets per engagement
- URL pipelines validate scope before any tool runs
- Attack-phase tools refuse out-of-scope targets
- sqlmap is double-gated (disabled by default + scope check)
- Attack phase requires explicit confirmation in UI

## Binds to 127.0.0.1 only.
