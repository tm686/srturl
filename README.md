# recon-runner

A local recon & testing orchestrator for authorized Synack Red Team (SRT)
engagements. Wraps standard recon/testing CLI tools behind a localhost-only web
UI, runs them in a proven order (modeled on ars0n-framework-v2's wildcard + URL
workflows), throttles them for non-disruptive testing, and consolidates output
into an ROI-ranked lead list.

Pure Python 3 standard library — no pip, no build step for the app itself.

---

## The environment this is built for

Runs inside **Kali WSL on a locked-down VMware Horizon VDI**. That box has TLS
inspection that breaks HTTPS fetches to PyPI / GitHub / registries, and the
system CA store can't be modified. So the design rule is:

> **Nothing is downloaded on the box.**

This splits the project into two halves that travel differently:

| Part | What it is | How it gets onto the box |
|---|---|---|
| **Source code** | this repo (small text files) | GitHub — clone, or browser "Download ZIP" if `git clone` is TLS-blocked |
| **Tool binaries + data** | subfinder, httpx, nuclei, … + nuclei-templates + wordlists (hundreds of MB) | **offline bundle** built on your host, transferred via sharefolder |

The binaries can't be pulled on the box no matter where they're hosted — that's
a TLS problem, below the public/private distinction. So the offline bundle step
does not go away.

---

## First-run sequence (the whole flow)

### On your HOST machine (unrestricted — home PC / home WSL)

**1. Get the source.**
```bash
git clone https://github.com/<owner>/recon-runner.git
cd recon-runner
```

**2. Build the offline bundle** (downloads all binaries, nuclei-templates,
wordlists, arjun wheels; produces `recon-runner-bundle.zip`):
```bash
bash bundle.sh
```
If a tool prints a `!!` "no asset matching" line, open that repo's latest
release, copy the real linux-amd64 filename fragment, and adjust the pattern in
`bundle.sh`. (Release asset names drift — `waybackurls` especially.)

**3. Move both into your sharefolder** — the bundle zip, and the source (zip the
repo too, or rely on cloning/ZIP on the box):
```
recon-runner-bundle.zip   ->  sharefolder
```

### On the HORIZON box (Kali WSL)

**4. Get the source onto the box.** Either:
```bash
git clone https://github.com/<owner>/recon-runner.git ~/recon-runner
```
…or, if `git clone` fails with `x509: certificate signed by unknown authority`,
download the repo ZIP through the browser and unzip it to `~/recon-runner`.

**5. Stage into the WSL filesystem — do NOT run from /mnt/c.**
WSL's access to the Windows filesystem (`/mnt/c/...`) is slow and mangles
`chmod +x` on the binaries. Copy the bundle into your Linux home first:
```bash
cd ~/recon-runner
cp /mnt/c/Users/<you>/Downloads/recon-runner-bundle.zip .
```

**6. Install (offline — no network calls).**
```bash
bash install.sh
```
This unzips the bundle, installs binaries to `/usr/local/bin` (falling back to
`./bin` if not writable), places templates/wordlists under `./data`, wraps
arjun/sqlmap, and writes `config/paths.json`.

**7. Confirm the ground before you trust it.**
```bash
python3 doctor.py
```
Expect `All critical checks passed`. Any `FAIL` on a core tool is a five-minute
binary fix now — much cheaper than discovering it mid-scan. `sqlmap`, `naabu`,
and `arjun` are optional; `WARN` on those is fine.

**8. Run.**
```bash
bash run.sh
```
Open `http://127.0.0.1:8777` in the box's browser.

---

## Daily use

1. Add a scope target — a **wildcard domain** (`*.example.com`) or a single
   **URL**. The UI shows only the tools valid for that target type.
2. Set the **throttle profile** (slider). **Stealth is the default** and the
   right SRT choice — slow, low-concurrency, delayed, to avoid disrupting the
   target. Move up only if the target clearly tolerates it.
3. **Wildcard:** run the rounds (passive → DNS → crawl, with httpx re-probing
   between each). At the decision point you get the **ROI Report** — each live
   host with a screenshot, metadata, and a score ranking likely-productive
   targets first.
4. **Promote** a high-ROI host from the report to a **URL target** — that
   unlocks the URL testing toolset (params, content, XSS, templated vulns),
   seeded from what recon already found so nothing is re-discovered.
5. Findings store request/response + screenshots and **export to JSON/CSV**,
   triage-ready for writing Synack submissions.

---

## Scope safety (read this)

Out-of-scope testing on SRT can get you removed from the platform. Every target
is validated against `config/scope.json` before any request leaves the box;
attack-phase tools refuse out-of-scope targets outright, and `sqlmap` is
double-gated and off by default. Keep `scope.json` accurate per engagement.

---

## Tuning (all in-place on the box — no re-transfer)

Everything you'd want to adjust is editable config; edit, restart `run.sh`:

- `config/tools.json` — tool commands/flags (reconcile against rs0n's exact
  flags here if they differ)
- `config/profiles.json` — throttle profiles; tune `stealth` rates per target
- `config/roi.json` — ROI scoring weights
- `config/scope.json` — the engagement's allowed domains/IPs

Only `bundle.sh`/`install.sh` (adding a new *binary*) require a new transfer.

---

## Known rough edges

- **arjun** needs `requests` — handled via offline wheels if `pip3` exists on
  the box; otherwise it's the one tool you may drop.
- **naabu** connect-scan (`-s c`) avoids needing root/libpcap, but may still be
  limited on some WSL kernels. httpx already covers common ports, so it's
  expendable.
- **nuclei** runs with `-duc` and points at the bundled templates — never calls
  `-update-templates` (which would hit the proxy). Refresh templates by
  rebuilding the bundle on your host.
