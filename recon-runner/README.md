# recon-runner

Local recon & testing orchestrator for authorized security engagements.
Pure Python 3 stdlib. Inspired by [ars0n-framework-v2](https://github.com/R-s0n/ars0n-framework-v2).

## Quick Start

```bash
# 1. Build offline bundle (on unrestricted host)
bash bundle.sh          # produces recon-runner-bundle.zip

# 2. Transfer bundle + repo to target machine

# 3. Install
bash install.sh         # extracts binaries, templates, wordlists

# 4. Run
bash run.sh             # http://127.0.0.1:8777
```

Options: `--daemon` (background), `--port PORT` (default 8777).

---

## Feature Guide

### Target Types

| Type | Input Example | What It Does |
|------|--------------|--------------|
| **Wildcard** | `example.com` | Enumerates all subdomains, probes for live hosts, screenshots, ROI scoring |
| **URL** | `https://app.example.com` | Deep testing of a single target — crawl, fuzz, scan for vulns |
| **IP / CIDR** | `10.0.0.0/24` | Port scan + HTTP probe of IP ranges |

### Pipelines

#### Wildcard Pipelines
| Pipeline | Steps | Use When |
|----------|-------|----------|
| **Full Recon (R1+R2+CeWL+R3)** | subfinder → dnsx → dnsx-brute → httpx → **CeWL** → dnsx-brute (CeWL wordlist) → httpx (new hosts) → screenshots → katana | Starting fresh on a new domain |
| **R1: Passive** | subfinder → dnsx → httpx → screenshots | Quick subdomain discovery |
| **R2: DNS Brute** | dnsx-brute → httpx (new hosts) | Expanding coverage after R1 |
| **R3: Crawl** | katana on all live URLs | Finding hidden endpoints/paths |

**CeWL enrichment step** (ars0n-framework inspired): After the initial httpx probe discovers live hosts, CeWL spiders them (`-d 2 -m 5 --with-numbers`) to extract target-specific words from page content. These words become subdomain candidates — a custom wordlist fed into a second dnsx brute-force pass. This discovers subdomains that generic wordlists miss (e.g., product names, internal terms, team names found on the target's website).

#### URL Pipelines
| Pipeline | Steps | Use When |
|----------|-------|----------|
| **Full URL (U1+U2+U3)** | gau + waybackurls → katana → arjun → ffuf → dalfox + nuclei | Complete deep test of a promoted target |
| **U1: Collect + Crawl** | gau + waybackurls → katana | Gathering URLs and endpoints |
| **U2: Params + Fuzz** | arjun → ffuf | Discovering hidden params and directories |
| **U3: Attack** | dalfox + nuclei | Active vulnerability scanning (requires confirmation) |

#### IP Pipeline
| Pipeline | Steps | Use When |
|----------|-------|----------|
| **IP Pipeline** | naabu → httpx → screenshots | Scanning IP ranges for web services |

### ROI Report

The ROI (Return on Investment) score ranks discovered URLs by how likely they are to yield vulnerabilities. Higher score = more interesting target.

**Scoring signals:**
- **missing_headers** — Missing security headers (X-Frame-Options, CSP, etc.) — more missing = higher score
- **tech** — Number of technologies detected (complex stacks have more attack surface)
- **endpoints** — Endpoint count (tiered: 5+/20+/50+ endpoints)
- **tls_issue** — Outdated TLS (1.0/1.1/SSL)
- **auth_surface** — 401/403 status codes suggest login/auth surfaces
- **error_page** — 500/502/503 indicate potential info leaks
- **complexity** — Title keywords (dashboard, admin, login, portal, api) and real app servers

**ROI Tiers:**
- **HIGH** (80+) — Investigate first
- **MED** (40-79) — Worth exploring
- **LOW** (1-39) — Lower priority

**ROI Report Modal:** Click "Open Report" to get a fullscreen paginated view of all targets, one per page, sorted high-to-low. Each page shows the URL, metadata, score breakdown, and a large screenshot. Navigate with arrow keys or Previous/Next buttons.

### Promote / Auto-Promote

- **Promote**: Marks a URL from the ROI report as a URL-target for deep testing (U1/U2/U3 pipelines). Click the "Promote" button on any ROI row.
- **Auto-Promote**: Automatically promotes all URLs above the configured ROI threshold (default 80). Runs after every wildcard pipeline or on button click.
- **Demote**: Undo a promotion (available in the ROI modal view).

### Recalculate

Recomputes ROI scores for all URLs using current data. Use after:
- Manually importing URLs
- New httpx data arrives from a re-probe
- Changing ROI weights in `config/roi.json`

### Scan Diff

Save snapshots of your current recon state (subdomains, URLs, hosts, findings) and compare between snapshots to spot new or removed assets.

1. Click **Save Snapshot** to capture current state
2. Select a snapshot in dropdown A
3. Leave B as "current" or select another snapshot
4. Click **Compare** to see added/removed assets

### Triage & Notes

Every ROI row and finding has:
- **Triage dropdown**: Mark as Interesting / Investigated / False Positive
- **Notes field**: Free-text notes for your records
- **Filter**: Filter ROI table or findings by triage status

### Engagements

Session isolation for different programs/targets:
- **Create**: Click "+" next to the engagement dropdown
- **Activate**: Select from dropdown — all new scans associate with this engagement
- **Clear**: Delete all data for the active engagement (or all data if none active)
- Scope settings load from the engagement's stored scope

### Nuclei Filters

When running URL pipelines that include nuclei:
- **Severity checkboxes**: Select which severities to scan for (critical/high/medium/low/info)
- **Tags field**: Comma-separated nuclei template tags (e.g., `cve,oast,sqli`)

### Per-Scan Results

Use the "View scan" dropdown (appears after first scan) to filter all data tables to a specific scan's results. Select "All scans" to return to the unfiltered view.

### Theme Toggle

Click **Light/Dark** in the header to switch between dark (default) and light themes. Preference is saved in localStorage.

### Import URLs

In URL target mode, click **Import URLs** to paste a list of URLs (one per line) for bulk import into the database.

---

## Button Reference

| Button | Location | Action |
|--------|----------|--------|
| **Run Workflow** | Target bar | Start the selected pipeline on the current target |
| **Stop** | Target bar (appears when running) | Terminate the running tool/pipeline |
| **Light / Dark** | Header | Toggle theme |
| **+** (New Engagement) | Engagement bar | Create a new engagement |
| **Clear** | Engagement bar | Clear data for active engagement |
| **Import URLs** | Target bar (URL mode) | Open bulk URL import modal |
| **Open Report** | ROI section | Open fullscreen paginated ROI report |
| **Auto-Promote** | ROI section | Promote all URLs above threshold |
| **Recalculate** | ROI section | Recompute all ROI scores |
| **Promote** | ROI table rows | Mark URL as target for deep testing |
| **Demote** | ROI modal | Undo promotion |
| **Export JSON** | Findings section | Download all findings as JSON |
| **Export CSV** | Findings section | Download all findings as CSV |
| **View** (Evidence) | Findings table | Show request/response evidence |
| **Save Snapshot** | Diff section | Save current state for comparison |
| **Compare** | Diff section | Diff two snapshots |
| **Clear** | Output pane | Clear the output log |
| Tool buttons | Tools panel | Run individual tools manually |

---

## Daily Workflow

1. **Create engagement** — Click "+", name it after the program
2. **Set scope** — Edit `config/scope.json` with allowed domains
3. **Enter wildcard target** — Type the root domain (e.g., `example.com`)
4. **Run Full Recon** — Click "Run Workflow" with "Full Recon (R1+R2+R3)" selected
5. **Review ROI report** — Click "Open Report" to page through targets high-to-low
6. **Promote high-ROI targets** — Click "Promote" on interesting ones (or use Auto-Promote)
7. **Switch to URL mode** — Change target type to "URL"
8. **Select promoted target** — Pick from the promoted dropdown
9. **Run URL pipeline** — Full URL or individual phases (U1/U2/U3)
10. **Confirm attack phase** — Approve when prompted for U3/Full
11. **Review findings** — Check severity, view evidence, triage
12. **Export** — Download JSON/CSV for reporting
13. **Save snapshot** — Preserve state for future diff comparison

---

## API Reference

### GET Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/doctor` | Preflight checks (tool availability) |
| `/api/tools` | Tool registry with availability status |
| `/api/profile` | Current throttle profile |
| `/api/scans` | List recent scans |
| `/api/stats` | Dashboard counts (subs, urls, hosts, findings) |
| `/api/events` | SSE event stream (live output) |
| `/api/subdomains?scan_id=N` | Subdomains (optionally filtered by scan) |
| `/api/urls?scan_id=N` | URLs with metadata (optionally filtered) |
| `/api/roi?scan_id=N` | ROI-ranked URLs (optionally filtered) |
| `/api/findings?scan_id=N` | Findings with dedup (optionally filtered) |
| `/api/promoted` | Promoted URL-targets |
| `/api/screenshots` | Available screenshot files |
| `/api/export/json` | Download all evidence as JSON |
| `/api/export/csv` | Download findings as CSV |
| `/api/engagements` | List engagements |
| `/api/snapshots` | List saved snapshots |
| `/api/diff?a=ID&b=ID` | Compare snapshots |
| `/api/config` | All configuration |

### POST Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/run` | Run a single tool |
| `/api/pipeline` | Run a multi-step pipeline |
| `/api/stop` | Stop running tool |
| `/api/profile` | Set throttle profile |
| `/api/roi/recalculate` | Recompute ROI scores |
| `/api/promote` | Promote URL to target |
| `/api/demote` | Demote URL target |
| `/api/auto-promote` | Auto-promote above threshold |
| `/api/notes` | Update triage/notes on URLs or findings |
| `/api/scope/check` | Check if URL is in scope |
| `/api/engagement` | Create engagement |
| `/api/engagement/activate` | Activate engagement |
| `/api/engagement/clear` | Clear engagement data |
| `/api/import/urls` | Bulk import URLs |
| `/api/snapshot` | Save snapshot |
| `/api/config/reload` | Reload config files |

---

## Configuration

All tunables live in `config/*.json`:

| File | Purpose |
|------|---------|
| `tools.json` | Tool registry — binaries, flags, phases, templates, target_types |
| `profiles.json` | Throttle profiles — stealth/slow/normal/fast (rate, threads, delay) |
| `roi.json` | ROI scoring weights and thresholds |
| `scope.json` | Allowed domains/IPs/CIDRs per engagement |
| `paths.json` | Tool and data paths (written by install.sh) |

---

## Scope Safety

- `config/scope.json` defines allowed targets per engagement
- URL pipelines validate scope before any tool runs
- Attack-phase tools refuse out-of-scope targets
- sqlmap is double-gated (disabled by default + scope check)
- Attack phase (U3) requires explicit confirmation in the UI
- Server binds to **127.0.0.1 only** — no external access
