#!/usr/bin/env python3
"""recon-runner preflight checks.

Standalone script AND importable module for the /doctor endpoint.
Checks: Python >= 3.8, stdlib imports, per-tool binary presence,
nuclei-templates + wordlists dirs, sqlite writable, version probes.
Exit nonzero on critical failure.
"""

import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_DIR = SCRIPT_DIR / "config"

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
SKIP = "SKIP"

# Tools that get a version probe (support --version or -version)
VERSION_PROBE_TOOLS = {"subfinder", "httpx", "nuclei"}

# Required stdlib modules the server imports
REQUIRED_STDLIB = [
    "http.server", "socketserver", "subprocess", "sqlite3", "json",
    "threading", "queue", "os", "pathlib", "html", "urllib", "shutil",
]


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return None


def check_python_version():
    v = sys.version_info
    ver_str = f"{v.major}.{v.minor}.{v.micro}"
    if (v.major, v.minor) >= (3, 8):
        return ("Python version", PASS, ver_str)
    return ("Python version", FAIL, f"{ver_str} — requires >= 3.8")


def check_stdlib_imports():
    failures = []
    for mod in REQUIRED_STDLIB:
        try:
            __import__(mod)
        except ImportError:
            failures.append(mod)
    if failures:
        return ("stdlib imports", FAIL, f"missing: {', '.join(failures)}")
    return ("stdlib imports", PASS, f"all {len(REQUIRED_STDLIB)} modules importable")


def check_config_files():
    results = []
    for name in ("tools.json", "profiles.json", "roi.json", "scope.json"):
        path = CONFIG_DIR / name
        data = load_json(path)
        if data is None:
            results.append((f"config/{name}", FAIL, "missing or invalid JSON"))
        else:
            results.append((f"config/{name}", PASS, "loaded"))
    return results


def check_paths_json():
    path = CONFIG_DIR / "paths.json"
    data = load_json(path)
    if data is None:
        return [("config/paths.json", WARN,
                 "not found — run install.sh or copy paths.json.example")]
    results = [("config/paths.json", PASS, "loaded")]
    for key in ("bin_dir", "nuclei_templates", "wordlists_dir", "db_path"):
        val = data.get(key, "")
        if val and key == "bin_dir":
            p = Path(val)
            if p.is_dir():
                results.append((f"  paths.bin_dir", PASS, str(p)))
            else:
                results.append((f"  paths.bin_dir", WARN, f"{p} — not found"))
    return results


def find_binary(name, bin_dir=None):
    """Find a binary, checking bin_dir first then PATH."""
    if bin_dir:
        candidate = Path(bin_dir) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return shutil.which(name)


def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def get_version(binary_path, name):
    """Try to get version string from a tool."""
    try:
        result = subprocess.run(
            [binary_path, "-version"],
            capture_output=True, text=True, timeout=10
        )
        output = strip_ansi((result.stdout + result.stderr).strip())
        for line in output.splitlines():
            line = line.strip()
            if line:
                return line[:80]
        return "unknown"
    except (subprocess.TimeoutExpired, OSError):
        return "version probe failed"


def check_tools():
    results = []
    tools_data = load_json(CONFIG_DIR / "tools.json")
    paths_data = load_json(CONFIG_DIR / "paths.json")
    bin_dir = paths_data.get("bin_dir", "") if paths_data else ""

    if tools_data is None:
        return [("tool detection", FAIL, "cannot load tools.json")]

    tools = tools_data.get("tools", {})
    for name, cfg in tools.items():
        binary = cfg.get("binary", name)
        optional = cfg.get("optional", False)
        enabled = cfg.get("enabled", True)

        path = find_binary(binary, bin_dir)
        if path:
            detail = f"found: {path}"
            if name in VERSION_PROBE_TOOLS:
                ver = get_version(path, name)
                detail += f" ({ver})"
            results.append((f"tool/{name}", PASS, detail))
        else:
            status = WARN if optional else FAIL
            tag = " (optional)" if optional else ""
            if not enabled:
                tag += " (disabled)"
                status = SKIP
            results.append((f"tool/{name}", status, f"not found{tag}"))

    return results


def check_nuclei_templates():
    paths_data = load_json(CONFIG_DIR / "paths.json")
    if not paths_data:
        return ("nuclei-templates", WARN, "paths.json missing — cannot check")
    tpl_dir = Path(paths_data.get("nuclei_templates", ""))
    if not tpl_dir.is_dir():
        return ("nuclei-templates", FAIL, f"{tpl_dir} — directory not found")
    # Check non-empty
    count = sum(1 for _ in tpl_dir.rglob("*.yaml"))
    if count == 0:
        return ("nuclei-templates", FAIL, f"{tpl_dir} — no .yaml files")
    return ("nuclei-templates", PASS, f"{tpl_dir} ({count} templates)")


def check_wordlists():
    paths_data = load_json(CONFIG_DIR / "paths.json")
    if not paths_data:
        return ("wordlists", WARN, "paths.json missing — cannot check")
    wl_dir = Path(paths_data.get("wordlists_dir", ""))
    if not wl_dir.is_dir():
        return ("wordlists", FAIL, f"{wl_dir} — directory not found")
    files = list(wl_dir.glob("*.txt"))
    if not files:
        return ("wordlists", FAIL, f"{wl_dir} — no .txt files")
    names = ", ".join(f.name for f in files[:5])
    suffix = f" +{len(files)-5} more" if len(files) > 5 else ""
    return ("wordlists", PASS, f"{wl_dir} ({names}{suffix})")


def check_sqlite():
    paths_data = load_json(CONFIG_DIR / "paths.json")
    if paths_data:
        db_path = Path(paths_data.get("db_path", ""))
        db_dir = db_path.parent
    else:
        db_dir = SCRIPT_DIR / "data"
        db_path = db_dir / "recon.db"

    # Test that we can create/write a sqlite db in the target directory
    db_dir.mkdir(parents=True, exist_ok=True)
    test_db = db_dir / ".doctor_test.db"
    try:
        conn = sqlite3.connect(str(test_db))
        conn.execute("CREATE TABLE IF NOT EXISTS _test (id INTEGER)")
        conn.execute("INSERT INTO _test VALUES (1)")
        conn.commit()
        conn.close()
        test_db.unlink()
        return ("sqlite writable", PASS, f"can write to {db_dir}")
    except Exception as e:
        return ("sqlite writable", FAIL, f"{db_dir} — {e}")


def run_checks():
    """Run all preflight checks. Returns list of (name, status, detail)."""
    results = []
    results.append(check_python_version())
    results.append(check_stdlib_imports())
    results.extend(check_config_files())
    results.extend(check_paths_json())
    results.extend(check_tools())
    results.append(check_nuclei_templates())
    results.append(check_wordlists())
    results.append(check_sqlite())
    return results


def results_to_dict(results):
    """Convert results to a JSON-serializable dict for the /doctor endpoint."""
    items = []
    has_critical_fail = False
    for name, status, detail in results:
        items.append({"check": name, "status": status, "detail": detail})
        if status == FAIL and not name.startswith("  "):
            has_critical_fail = True
    return {
        "ok": not has_critical_fail,
        "checks": items,
    }


def main():
    results = run_checks()
    critical_fail = False
    for name, status, detail in results:
        if status == PASS:
            sym = "\033[32m✓\033[0m"
        elif status == FAIL:
            sym = "\033[31m✗\033[0m"
            if not name.startswith("  "):
                critical_fail = True
        elif status == WARN:
            sym = "\033[33m!\033[0m"
        else:
            sym = "\033[90m-\033[0m"
        print(f"  {sym} [{status:4s}] {name}: {detail}")

    print()
    if critical_fail:
        print("\033[31mPREFLIGHT FAILED\033[0m — fix critical issues above")
        sys.exit(1)
    else:
        print("\033[32mPREFLIGHT PASSED\033[0m")


if __name__ == "__main__":
    main()
