#!/usr/bin/env python3
"""recon-runner — Local Recon & Testing Orchestrator.

Pure Python 3 stdlib HTTP server. Entry point.
Bind 127.0.0.1 only. Serves web/ from disk, exposes API + SSE endpoints,
manages SQLite DB, reads config/*.json.

Usage:
    python3 server.py --host 127.0.0.1 --port 8777
"""

import argparse
import json
import os
import shutil
import socketserver
import sqlite3
import subprocess
import tempfile
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from queue import Queue, Empty
from urllib.parse import urlparse, parse_qs


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Handle each request in a new thread — required for SSE + concurrent API."""
    daemon_threads = True

import doctor

SCRIPT_DIR = Path(__file__).resolve().parent
WEB_DIR = SCRIPT_DIR / "web"
CONFIG_DIR = SCRIPT_DIR / "config"

# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

class Config:
    """Loads and caches all config/*.json files. Thread-safe reload."""

    def __init__(self):
        self._lock = threading.Lock()
        self.tools = {}
        self.profiles = {}
        self.roi = {}
        self.scope = {}
        self.paths = {}
        self.active_profile = "stealth"
        self.reload()

    def _load(self, name):
        path = CONFIG_DIR / name
        try:
            with open(path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def reload(self):
        with self._lock:
            self.tools = self._load("tools.json")
            self.profiles = self._load("profiles.json")
            self.roi = self._load("roi.json")
            self.scope = self._load("scope.json")
            self.paths = self._load("paths.json")
            default = self.profiles.get("default_profile", "stealth")
            if self.active_profile not in self.profiles.get("profiles", {}):
                self.active_profile = default

    def get_profile_values(self, name=None):
        """Return the merged throttle dict for a profile name."""
        name = name or self.active_profile
        return self.profiles.get("profiles", {}).get(name, {})

    def get_nuclei_defaults(self):
        return self.profiles.get("nuclei_defaults", {})

    def get_bin_dir(self):
        return self.paths.get("bin_dir", "")

    def get_tool_spec(self, tool_name):
        return self.tools.get("tools", {}).get(tool_name)


# ---------------------------------------------------------------------------
# Tool availability detection
# ---------------------------------------------------------------------------

def detect_tools(cfg):
    """Return dict of tool_name -> {available, path, binary, enabled, optional, phase, target_types}."""
    bin_dir = cfg.get_bin_dir()
    registry = cfg.tools.get("tools", {})
    result = {}
    for name, spec in registry.items():
        # Try binary_aliases first, fall back to binary field
        aliases = spec.get("binary_aliases", [spec.get("binary", name)])
        found_path = None
        found_binary = None
        for alias in aliases:
            p = doctor.find_binary(alias, bin_dir)
            if p:
                found_path = p
                found_binary = alias
                break
        result[name] = {
            "available": found_path is not None,
            "path": found_path or "",
            "binary": found_binary or aliases[0],
            "enabled": spec.get("enabled", True),
            "optional": spec.get("optional", False),
            "gated": spec.get("gated", False),
            "phase": spec.get("phase", ""),
            "target_types": spec.get("target_types", []),
        }
    return result


# ---------------------------------------------------------------------------
# SSE Event Bus
# ---------------------------------------------------------------------------

class EventBus:
    """Fan-out event bus for SSE clients. Thread-safe."""

    def __init__(self):
        self._lock = threading.Lock()
        self._subscribers = []

    def subscribe(self):
        q = Queue()
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def publish(self, event, data):
        """Publish an event to all subscribers."""
        msg = {"event": event, "data": data, "ts": time.time()}
        with self._lock:
            for q in self._subscribers:
                q.put(msg)


# Global event bus
event_bus = EventBus()


# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK(target_type IN ('wildcard','url')),
    round       INTEGER DEFAULT 0,
    profile     TEXT NOT NULL DEFAULT 'stealth',
    started_at  TEXT DEFAULT (datetime('now')),
    status      TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS subdomains (
    fqdn        TEXT PRIMARY KEY,
    resolved_ip TEXT DEFAULT '',
    sources     TEXT DEFAULT '[]',
    scan_id     INTEGER REFERENCES scans(id),
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS hosts (
    ip          TEXT NOT NULL,
    port        INTEGER NOT NULL,
    service     TEXT DEFAULT '',
    sources     TEXT DEFAULT '[]',
    scan_id     INTEGER REFERENCES scans(id),
    created_at  TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (ip, port)
);

CREATE TABLE IF NOT EXISTS urls (
    url                 TEXT PRIMARY KEY,
    status_code         INTEGER,
    title               TEXT DEFAULT '',
    tech                TEXT DEFAULT '',
    server              TEXT DEFAULT '',
    tls_state           TEXT DEFAULT '',
    missing_headers     TEXT DEFAULT '[]',
    endpoint_count      INTEGER DEFAULT 0,
    screenshot_path     TEXT DEFAULT '',
    roi_score           INTEGER DEFAULT 0,
    promoted_to_target  INTEGER DEFAULT 0,
    sources             TEXT DEFAULT '[]',
    scan_id             INTEGER REFERENCES scans(id),
    created_at          TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS params (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL,
    name        TEXT NOT NULL,
    method      TEXT DEFAULT 'GET',
    source_tool TEXT DEFAULT '',
    scan_id     INTEGER REFERENCES scans(id),
    created_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(url, name, method)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL,
    vector      TEXT DEFAULT '',
    template_id TEXT DEFAULT '',
    severity    TEXT DEFAULT '',
    tool        TEXT DEFAULT '',
    request     TEXT DEFAULT '',
    response    TEXT DEFAULT '',
    sources     TEXT DEFAULT '[]',
    scan_id     INTEGER REFERENCES scans(id),
    created_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(url, vector, template_id)
);
"""

_db_lock = threading.Lock()


def init_db(db_path):
    """Create/open the database and ensure schema exists."""
    db_dir = Path(db_path).parent
    db_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# DB upsert helpers
# ---------------------------------------------------------------------------

def _merge_sources(existing_json, new_source):
    """Merge a new source into the existing sources JSON array."""
    try:
        sources = json.loads(existing_json) if existing_json else []
    except (json.JSONDecodeError, TypeError):
        sources = []
    if new_source and new_source not in sources:
        sources.append(new_source)
    return json.dumps(sources)


def upsert_subdomain(db, fqdn, resolved_ip="", source="", scan_id=None):
    with _db_lock:
        row = db.execute("SELECT sources FROM subdomains WHERE fqdn=?", (fqdn,)).fetchone()
        sources = _merge_sources(row["sources"] if row else "[]", source)
        if row:
            db.execute(
                "UPDATE subdomains SET resolved_ip=COALESCE(NULLIF(?,''),resolved_ip), sources=? WHERE fqdn=?",
                (resolved_ip, sources, fqdn))
        else:
            db.execute(
                "INSERT INTO subdomains (fqdn, resolved_ip, sources, scan_id) VALUES (?,?,?,?)",
                (fqdn, resolved_ip, sources, scan_id))
        db.commit()


def upsert_host(db, ip, port, service="", source="", scan_id=None):
    with _db_lock:
        row = db.execute("SELECT sources FROM hosts WHERE ip=? AND port=?", (ip, port)).fetchone()
        sources = _merge_sources(row["sources"] if row else "[]", source)
        if row:
            db.execute(
                "UPDATE hosts SET service=COALESCE(NULLIF(?,''),service), sources=? WHERE ip=? AND port=?",
                (service, sources, ip, port))
        else:
            db.execute(
                "INSERT INTO hosts (ip, port, service, sources, scan_id) VALUES (?,?,?,?,?)",
                (ip, port, service, sources, scan_id))
        db.commit()


def upsert_url(db, url, source="", scan_id=None, **kwargs):
    with _db_lock:
        row = db.execute("SELECT sources FROM urls WHERE url=?", (url,)).fetchone()
        sources = _merge_sources(row["sources"] if row else "[]", source)
        if row:
            sets = ["sources=?"]
            vals = [sources]
            for k, v in kwargs.items():
                if v is not None and v != "":
                    sets.append(f"{k}=?")
                    vals.append(v)
            vals.append(url)
            db.execute(f"UPDATE urls SET {','.join(sets)} WHERE url=?", vals)
        else:
            cols = ["url", "sources", "scan_id"]
            vals = [url, sources, scan_id]
            for k, v in kwargs.items():
                if v is not None:
                    cols.append(k)
                    vals.append(v)
            placeholders = ",".join("?" * len(cols))
            db.execute(f"INSERT INTO urls ({','.join(cols)}) VALUES ({placeholders})", vals)
        db.commit()


def upsert_param(db, url, name, method="GET", source_tool="", scan_id=None):
    with _db_lock:
        db.execute(
            "INSERT OR IGNORE INTO params (url, name, method, source_tool, scan_id) VALUES (?,?,?,?,?)",
            (url, name, method, source_tool, scan_id))
        db.commit()


def upsert_finding(db, url, vector="", template_id="", severity="", tool="",
                   request="", response="", source="", scan_id=None):
    with _db_lock:
        row = db.execute(
            "SELECT id, sources FROM findings WHERE url=? AND vector=? AND template_id=?",
            (url, vector, template_id)).fetchone()
        sources = _merge_sources(row["sources"] if row else "[]", source)
        if row:
            db.execute(
                "UPDATE findings SET severity=?, request=?, response=?, sources=? WHERE id=?",
                (severity, request, response, sources, row["id"]))
        else:
            db.execute(
                "INSERT INTO findings (url,vector,template_id,severity,tool,request,response,sources,scan_id)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (url, vector, template_id, severity, tool, request, response, sources, scan_id))
        db.commit()


# ---------------------------------------------------------------------------
# JSONL parsers — per-tool extraction
# ---------------------------------------------------------------------------

def parse_subfinder(obj, db, scan_id):
    host = obj.get("host", "")
    ip = obj.get("ip", "")
    if host:
        upsert_subdomain(db, host, resolved_ip=ip, source="subfinder", scan_id=scan_id)
    return host

def parse_dnsx(obj, db, scan_id):
    host = obj.get("host", "")
    a_records = obj.get("a", [])
    ip = a_records[0] if a_records else ""
    if host:
        upsert_subdomain(db, host, resolved_ip=ip, source="dnsx", scan_id=scan_id)
    return host

def parse_httpx(obj, db, scan_id):
    url = obj.get("url", "")
    if not url:
        return ""
    tech_list = obj.get("tech", [])
    tech = ", ".join(tech_list) if isinstance(tech_list, list) else str(tech_list)
    missing = obj.get("missing_headers", "[]")
    if isinstance(missing, list):
        missing = json.dumps(missing)

    # Normalize screenshot path — use relative path from httpx or extract from absolute
    ss_path = obj.get("screenshot_path_rel", "") or obj.get("screenshot_path", "") or obj.get("screenshot-path", "")
    if ss_path and "/" in ss_path:
        # If absolute, extract the host/hash.png portion after "screenshot/" dir
        parts = ss_path.replace("\\", "/").split("/")
        try:
            idx = parts.index("screenshot")
            ss_path = "/".join(parts[idx + 1:])
        except ValueError:
            ss_path = "/".join(parts[-2:])  # fallback: host/hash.png

    upsert_url(db, url, source="httpx", scan_id=scan_id,
               status_code=obj.get("status_code") or obj.get("status-code"),
               title=obj.get("title", ""),
               tech=tech,
               server=obj.get("webserver", ""),
               tls_state=obj.get("tls", {}).get("version", "") if isinstance(obj.get("tls"), dict) else "",
               screenshot_path=ss_path)
    return url

def parse_naabu(obj, db, scan_id):
    ip = obj.get("ip", obj.get("host", ""))
    port = obj.get("port", 0)
    if ip and port:
        upsert_host(db, ip, int(port), source="naabu", scan_id=scan_id)
    return f"{ip}:{port}"

def parse_katana(obj, db, scan_id):
    endpoint = obj.get("request", {}).get("endpoint", "") if isinstance(obj.get("request"), dict) else ""
    if not endpoint:
        endpoint = obj.get("endpoint", obj.get("url", ""))
    if endpoint:
        upsert_url(db, endpoint, source="katana", scan_id=scan_id)
    return endpoint

def parse_gau(obj, db, scan_id):
    url = obj.get("url", "")
    if url:
        upsert_url(db, url, source="gau", scan_id=scan_id)
    return url

def parse_nuclei(obj, db, scan_id):
    url = obj.get("matched-at", obj.get("host", ""))
    template_id = obj.get("template-id", "")
    severity = obj.get("info", {}).get("severity", "") if isinstance(obj.get("info"), dict) else ""
    matcher = obj.get("matcher-name", "")
    req = obj.get("request", "")
    resp = obj.get("response", "")
    if url:
        upsert_finding(db, url, vector=matcher, template_id=template_id,
                       severity=severity, tool="nuclei", request=req,
                       response=resp, source="nuclei", scan_id=scan_id)
    return f"{template_id} [{severity}] {url}"

def parse_dalfox(obj, db, scan_id):
    url = obj.get("data", "")
    poc = obj.get("poc", "")
    if url or poc:
        target_url = url or poc
        upsert_finding(db, target_url, vector=obj.get("param", ""),
                       template_id="xss", severity=obj.get("severity", "medium"),
                       tool="dalfox", source="dalfox", scan_id=scan_id)
    return url or poc

# For tools with file_json output, parsed on completion
def parse_ffuf_file(filepath, db, scan_id):
    try:
        with open(filepath) as f:
            data = json.load(f)
        for result in data.get("results", []):
            url = result.get("url", "")
            status = result.get("status", 0)
            if url:
                upsert_url(db, url, source="ffuf", scan_id=scan_id, status_code=status)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

def parse_arjun_file(filepath, db, scan_id):
    try:
        with open(filepath) as f:
            data = json.load(f)
        for url, params in data.items():
            if isinstance(params, list):
                for p in params:
                    upsert_param(db, url, p, source_tool="arjun", scan_id=scan_id)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

def parse_nuclei_file(filepath, db, scan_id):
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line:
                    obj = json.loads(line)
                    parse_nuclei(obj, db, scan_id)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

PARSERS = {
    "subfinder": parse_subfinder,
    "dnsx": parse_dnsx,
    "dnsx-brute": parse_dnsx,
    "httpx": parse_httpx,
    "httpx-screenshot": parse_httpx,
    "naabu": parse_naabu,
    "katana": parse_katana,
    "gau": parse_gau,
    "nuclei": parse_nuclei,
    "dalfox": parse_dalfox,
}

FILE_PARSERS = {
    "ffuf": parse_ffuf_file,
    "arjun": parse_arjun_file,
    "nuclei": parse_nuclei_file,
}


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------

class ToolRunner:
    """Runs a tool subprocess, streams output via SSE, upserts to DB."""

    def __init__(self, cfg, db, tool_status):
        self.cfg = cfg
        self.db = db
        self.tool_status = tool_status
        self._current_proc = None
        self._stop_flag = threading.Event()

    def _resolve_dns_wordlist(self):
        """Find best DNS brute wordlist: paths.json > SecLists > system."""
        # 1. Explicit config
        configured = self.cfg.paths.get("dns_wordlist", "")
        if configured and Path(configured).is_file():
            return configured
        # 2. SecLists standard paths
        for candidate in [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        ]:
            if Path(candidate).is_file():
                return candidate
        # 3. Bundled wordlists dir
        wl_dir = self.cfg.paths.get("wordlists_dir", "")
        if wl_dir:
            for name in ["dns-subdomains.txt", "subdomains.txt"]:
                p = Path(wl_dir) / name
                if p.is_file():
                    return str(p)
        return ""

    def _resolve_screenshots_dir(self):
        """Resolve screenshots directory, creating if needed."""
        configured = self.cfg.paths.get("screenshots_dir", "")
        if configured:
            p = Path(configured)
        else:
            p = SCRIPT_DIR / "data" / "screenshots"
        p.mkdir(parents=True, exist_ok=True)
        return str(p.resolve())

    def build_cmd(self, tool_name, context):
        """Substitute throttle profile + context values into tool template."""
        spec = self.cfg.get_tool_spec(tool_name)
        if not spec:
            return None, None, f"unknown tool: {tool_name}"

        # Check availability
        status = self.tool_status.get(tool_name, {})
        if not status.get("available"):
            return None, None, f"{tool_name}: binary not found"
        if not spec.get("enabled", True):
            return None, None, f"{tool_name}: disabled"

        template = spec.get("template", "")
        output_mode = spec.get("output", "stdout_jsonl")

        # Resolve actual binary name (may differ from tool name via aliases)
        resolved_binary = status.get("binary", spec.get("binary", tool_name))
        template = template.replace("{_binary}", resolved_binary)

        # Merge profile values + nuclei defaults + context
        values = {}
        values.update(self.cfg.get_profile_values())
        values.update(self.cfg.get_nuclei_defaults())

        # Paths from config
        values["nuclei_templates"] = self.cfg.paths.get("nuclei_templates", "")
        values["wordlist"] = ""  # caller sets
        wl_dir = self.cfg.paths.get("wordlists_dir", "")
        if wl_dir:
            # default wordlist for ffuf
            candidate = Path(wl_dir) / "raft-medium-directories.txt"
            if candidate.exists():
                values["wordlist"] = str(candidate)

        # DNS wordlist for dnsx-brute
        values["dns_wordlist"] = self._resolve_dns_wordlist()

        # Screenshots directory
        values["screenshots_dir"] = self._resolve_screenshots_dir()

        values.update(context)

        # Generate out_file for file-output tools
        if "{out_file}" in template:
            out_file = tempfile.mktemp(suffix=f".{tool_name}.json",
                                       dir=str(SCRIPT_DIR / "data"))
            values["out_file"] = out_file
        else:
            out_file = None

        # Substitute — only replace keys that exist in template
        cmd_str = template
        for k, v in values.items():
            cmd_str = cmd_str.replace("{" + k + "}", str(v))

        return cmd_str, out_file, None

    def run_tool(self, tool_name, context, scan_id=None):
        """Run a single tool. Blocking — call from a thread."""
        self._stop_flag.clear()
        spec = self.cfg.get_tool_spec(tool_name)
        if not spec:
            event_bus.publish("error", {"tool": tool_name, "message": f"unknown tool: {tool_name}"})
            return

        cmd_str, out_file, err = self.build_cmd(tool_name, context)
        if err:
            event_bus.publish("error", {"tool": tool_name, "message": err})
            return

        output_mode = spec.get("output", "stdout_jsonl")
        parser_fn = PARSERS.get(tool_name)
        bin_dir = self.cfg.get_bin_dir()

        event_bus.publish("tool_start", {
            "tool": tool_name,
            "cmd": cmd_str,
            "profile": self.cfg.active_profile,
            "values": self.cfg.get_profile_values(),
        })

        env = os.environ.copy()
        if bin_dir:
            env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")

        try:
            proc = subprocess.Popen(
                cmd_str.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=str(SCRIPT_DIR),
            )
            self._current_proc = proc

            # Stream stdout and stderr in parallel threads
            parsed_count = [0]
            stdout_done = threading.Event()
            stderr_done = threading.Event()

            def read_stdout():
                for raw_line in proc.stdout:
                    if self._stop_flag.is_set():
                        break
                    line = raw_line.decode("utf-8", errors="replace").rstrip()
                    if not line:
                        continue

                    if output_mode == "stdout_jsonl":
                        try:
                            obj = json.loads(line)
                            summary = ""
                            if parser_fn:
                                summary = parser_fn(obj, self.db, scan_id)
                            event_bus.publish("stdout", {
                                "tool": tool_name, "type": "json",
                                "line": line, "summary": summary,
                            })
                            parsed_count[0] += 1
                        except json.JSONDecodeError:
                            event_bus.publish("stdout", {
                                "tool": tool_name, "type": "text", "line": line,
                            })
                    elif output_mode == "stdout_lines":
                        # Plain text lines (waybackurls, sqlmap)
                        if tool_name == "waybackurls" and line.startswith("http"):
                            upsert_url(self.db, line.strip(), source="waybackurls", scan_id=scan_id)
                            parsed_count[0] += 1
                        event_bus.publish("stdout", {
                            "tool": tool_name, "type": "text", "line": line,
                        })
                    else:
                        # file_json / file_jsonl — still stream stderr, stdout may be empty
                        event_bus.publish("stdout", {
                            "tool": tool_name, "type": "text", "line": line,
                        })
                stdout_done.set()

            def read_stderr():
                for raw_line in proc.stderr:
                    if self._stop_flag.is_set():
                        break
                    line = raw_line.decode("utf-8", errors="replace").rstrip()
                    if line:
                        event_bus.publish("stderr", {
                            "tool": tool_name, "line": line,
                        })
                stderr_done.set()

            t_out = threading.Thread(target=read_stdout, daemon=True)
            t_err = threading.Thread(target=read_stderr, daemon=True)
            t_out.start()
            t_err.start()

            proc.wait()
            t_out.join(timeout=5)
            t_err.join(timeout=5)

            # Parse file output on completion
            if out_file and os.path.exists(out_file):
                file_parser = FILE_PARSERS.get(tool_name)
                if file_parser:
                    file_parser(out_file, self.db, scan_id)
                    event_bus.publish("stdout", {
                        "tool": tool_name, "type": "text",
                        "line": f"[*] Parsed output file: {out_file}",
                    })

            exit_code = proc.returncode
            event_bus.publish("tool_done", {
                "tool": tool_name,
                "exit_code": exit_code,
                "parsed": parsed_count[0],
            })

        except FileNotFoundError:
            event_bus.publish("error", {
                "tool": tool_name,
                "message": f"binary not found: {cmd_str.split()[0]}",
            })
        except Exception as e:
            event_bus.publish("error", {
                "tool": tool_name, "message": str(e),
            })
        finally:
            self._current_proc = None

    def stop(self):
        """Stop the currently running tool."""
        self._stop_flag.set()
        proc = self._current_proc
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Consolidation — between-round data extraction + temp file generation
# ---------------------------------------------------------------------------

def consolidate_subdomains(db, scan_id=None):
    """Extract ALL subdomains from DB, write to temp file. Returns (filepath, count).
    scan_id is accepted for API compatibility but not used for filtering —
    consolidation always gathers everything known so far."""
    with _db_lock:
        rows = db.execute("SELECT fqdn FROM subdomains").fetchall()
    fqdns = sorted(set(r["fqdn"] for r in rows if r["fqdn"]))
    if not fqdns:
        return None, 0
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".subs.txt",
                                      dir=str(SCRIPT_DIR / "data"),
                                      delete=False)
    tmp.write("\n".join(fqdns) + "\n")
    tmp.close()
    return tmp.name, len(fqdns)


def consolidate_resolved(db, scan_id=None):
    """Extract resolved subdomains (have IP), write to temp file. Returns (filepath, count)."""
    with _db_lock:
        rows = db.execute(
            "SELECT fqdn FROM subdomains WHERE resolved_ip != ''").fetchall()
    fqdns = sorted(set(r["fqdn"] for r in rows if r["fqdn"]))
    if not fqdns:
        return None, 0
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".resolved.txt",
                                      dir=str(SCRIPT_DIR / "data"),
                                      delete=False)
    tmp.write("\n".join(fqdns) + "\n")
    tmp.close()
    return tmp.name, len(fqdns)


def consolidate_live_urls(db, scan_id=None):
    """Extract live URLs from DB, write to temp file. Returns (filepath, count)."""
    with _db_lock:
        rows = db.execute("SELECT url FROM urls").fetchall()
    urls = sorted(set(r["url"] for r in rows if r["url"]))
    if not urls:
        return None, 0
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".urls.txt",
                                      dir=str(SCRIPT_DIR / "data"),
                                      delete=False)
    tmp.write("\n".join(urls) + "\n")
    tmp.close()
    return tmp.name, len(urls)


def consolidate_all_hosts(db, scan_id=None):
    """Extract ALL subdomains (across all scans), write to temp file."""
    with _db_lock:
        rows = db.execute("SELECT fqdn FROM subdomains").fetchall()
    fqdns = sorted(set(r["fqdn"] for r in rows if r["fqdn"]))
    if not fqdns:
        return None, 0
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".all-subs.txt",
                                      dir=str(SCRIPT_DIR / "data"),
                                      delete=False)
    tmp.write("\n".join(fqdns) + "\n")
    tmp.close()
    return tmp.name, len(fqdns)


def consolidate_unprobed_hosts(db, scan_id=None):
    """Extract subdomains that have no matching URL entry yet. For R2 re-probe."""
    with _db_lock:
        # Get all subdomains that aren't already covered by a URL
        rows = db.execute(
            "SELECT s.fqdn FROM subdomains s "
            "WHERE NOT EXISTS ("
            "  SELECT 1 FROM urls u WHERE u.url LIKE '%' || s.fqdn || '%'"
            ")"
        ).fetchall()
    fqdns = sorted(set(r["fqdn"] for r in rows if r["fqdn"]))
    if not fqdns:
        return None, 0
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".unprobed.txt",
                                      dir=str(SCRIPT_DIR / "data"),
                                      delete=False)
    tmp.write("\n".join(fqdns) + "\n")
    tmp.close()
    return tmp.name, len(fqdns)


# ---------------------------------------------------------------------------
# Pipeline runner — chains tools with consolidation between steps
# ---------------------------------------------------------------------------

class PipelineRunner:
    """Runs a sequence of (tool, consolidate_fn) steps.

    Each step:
    1. Run consolidation function to generate input file for the tool
    2. Run the tool with the generated input
    3. Publish pipeline progress via SSE
    Stops if stop_flag is set or if a required tool is unavailable.
    """

    def __init__(self, tool_runner):
        self.runner = tool_runner
        self._stop_flag = tool_runner._stop_flag

    def run_pipeline(self, steps, target, target_type, scan_id):
        """Run a list of pipeline steps. Each step is a dict:
        {
            "tool": tool_name,
            "consolidate": callable(db, scan_id) -> (filepath, count) or None,
            "context_key": key name for the consolidated file in context ("in_file", "subs_file", etc)
            "required": bool — if True, skip rest if tool missing
            "label": human-readable step description
        }
        """
        total = len(steps)
        for i, step in enumerate(steps):
            if self._stop_flag.is_set():
                event_bus.publish("pipeline_done", {
                    "message": "Pipeline stopped by user",
                    "steps": i,
                })
                return

            tool_name = step["tool"]
            label = step.get("label", tool_name)
            required = step.get("required", True)

            event_bus.publish("pipeline_step", {
                "step": i + 1, "total": total,
                "tool": tool_name, "label": label,
            })

            # Check tool availability
            status = self.runner.tool_status.get(tool_name, {})
            if not status.get("available"):
                msg = f"{tool_name}: binary not found"
                if required:
                    event_bus.publish("error", {"tool": tool_name, "message": msg + " (required — stopping pipeline)"})
                    event_bus.publish("pipeline_done", {"message": "Pipeline stopped (missing required tool)", "steps": i})
                    return
                else:
                    event_bus.publish("pipeline_info", {"message": f"Skipping {tool_name} (not installed)", "step": i + 1, "total": total})
                    continue

            # Run consolidation if specified
            context = {"target": target, "host": target, "url": target}
            consolidate_fn = step.get("consolidate")
            context_key = step.get("context_key", "in_file")

            if consolidate_fn:
                filepath, count = consolidate_fn(self.runner.db, scan_id)
                if not filepath or count == 0:
                    event_bus.publish("pipeline_info", {
                        "message": f"Consolidation for {tool_name}: 0 inputs — skipping",
                        "step": i + 1, "total": total,
                    })
                    continue
                context[context_key] = filepath
                event_bus.publish("pipeline_info", {
                    "message": f"Consolidated {count} inputs for {tool_name} -> {filepath}",
                    "step": i + 1, "total": total,
                })

            # Run the tool (blocking)
            self.runner.run_tool(tool_name, context, scan_id=scan_id)

            # Clean up temp file
            if consolidate_fn and filepath:
                try:
                    os.unlink(filepath)
                except OSError:
                    pass

        event_bus.publish("pipeline_done", {
            "message": "Pipeline complete",
            "steps": total,
        })


# ---------------------------------------------------------------------------
# Pipeline definitions — R1, R2, R3, full wildcard
# ---------------------------------------------------------------------------

def build_r1_steps(scan_id):
    """R1 passive: subfinder -> dnsx -> httpx probe -> screenshots"""
    return [
        {
            "tool": "subfinder",
            "label": "R1: Passive subdomain enumeration",
            "required": True,
        },
        {
            "tool": "dnsx",
            "consolidate": consolidate_subdomains,
            "context_key": "in_file",
            "label": "R1: DNS resolution",
            "required": True,
        },
        {
            "tool": "httpx",
            "consolidate": consolidate_all_hosts,
            "context_key": "in_file",
            "label": "R1: HTTP probe",
            "required": True,
        },
        {
            "tool": "httpx-screenshot",
            "consolidate": consolidate_live_urls,
            "context_key": "in_file",
            "label": "R1: Screenshots",
            "required": False,
        },
    ]


def build_r2_steps(scan_id):
    """R2 active: dnsx brute force -> consolidate new subs -> httpx re-probe"""
    return [
        {
            "tool": "dnsx-brute",
            "label": "R2: DNS brute force",
            "required": True,
        },
        {
            "tool": "httpx",
            "consolidate": consolidate_unprobed_hosts,
            "context_key": "in_file",
            "label": "R2: HTTP probe (new hosts)",
            "required": True,
        },
    ]


def build_r3_steps(scan_id):
    """R3 crawl: katana crawl all live URLs for endpoint discovery"""
    return [
        {
            "tool": "katana",
            "consolidate": consolidate_live_urls,
            "context_key": "in_file",
            "label": "R3: Crawl live URLs",
            "required": True,
        },
    ]


def build_wildcard_steps(scan_id):
    """Full wildcard pipeline: R1 (passive) + R2 (brute) + R3 (crawl) + screenshots"""
    return [
        # R1: Passive enumeration
        {
            "tool": "subfinder",
            "label": "R1: Passive subdomain enumeration",
            "required": True,
        },
        {
            "tool": "dnsx",
            "consolidate": consolidate_subdomains,
            "context_key": "in_file",
            "label": "R1: DNS resolution",
            "required": True,
        },
        # R2: DNS brute force
        {
            "tool": "dnsx-brute",
            "label": "R2: DNS brute force",
            "required": False,
        },
        # Combined HTTP probe (covers R1 + R2 results in one pass)
        {
            "tool": "httpx",
            "consolidate": consolidate_all_hosts,
            "context_key": "in_file",
            "label": "HTTP probe (all hosts)",
            "required": True,
        },
        # Screenshots of live URLs
        {
            "tool": "httpx-screenshot",
            "consolidate": consolidate_live_urls,
            "context_key": "in_file",
            "label": "Screenshots",
            "required": False,
        },
        # R3: Crawl live URLs
        {
            "tool": "katana",
            "consolidate": consolidate_live_urls,
            "context_key": "in_file",
            "label": "R3: Crawl live URLs",
            "required": False,
        },
    ]


# Global runner instance (set in main)
runner = None
pipeline_runner = None


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class ReconHandler(SimpleHTTPRequestHandler):
    """Routes /api/* to handlers, everything else to web/ static files."""

    # Set by main() before server starts
    cfg = None
    db = None
    tool_status = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    # --- Routing -----------------------------------------------------------

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        routes = {
            "/api/doctor":          self.handle_doctor,
            "/api/config":          self.handle_config_all,
            "/api/config/tools":    lambda: self.handle_config_file("tools"),
            "/api/config/profiles": lambda: self.handle_config_file("profiles"),
            "/api/config/roi":      lambda: self.handle_config_file("roi"),
            "/api/config/scope":    lambda: self.handle_config_file("scope"),
            "/api/config/paths":    lambda: self.handle_config_file("paths"),
            "/api/tools":           self.handle_tools,
            "/api/profile":         self.handle_get_profile,
            "/api/scans":           self.handle_list_scans,
            "/api/stats":           self.handle_stats,
            "/api/events":          self.handle_sse,
            "/api/subdomains":      self.handle_subdomains,
            "/api/urls":            self.handle_urls,
            "/api/screenshots":     self.handle_screenshots_list,
        }

        handler = routes.get(path)
        if handler:
            handler()
        elif path.startswith("/screenshots/"):
            self.handle_serve_screenshot(path)
        elif path.startswith("/api/"):
            self.send_json({"error": "not found"}, 404)
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/profile":
            self.handle_set_profile()
        elif path == "/api/config/reload":
            self.handle_config_reload()
        elif path == "/api/run":
            self.handle_run_tool()
        elif path == "/api/pipeline":
            self.handle_run_pipeline()
        elif path == "/api/stop":
            self.handle_stop_tool()
        elif path.startswith("/api/"):
            self.send_json({"error": "not found"}, 404)
        else:
            self.send_json({"error": "method not allowed"}, 405)

    # --- API handlers ------------------------------------------------------

    def handle_doctor(self):
        results = doctor.run_checks()
        self.send_json(doctor.results_to_dict(results))

    def handle_config_all(self):
        self.send_json({
            "tools": self.cfg.tools,
            "profiles": self.cfg.profiles,
            "roi": self.cfg.roi,
            "scope": self.cfg.scope,
            "paths": self.cfg.paths,
            "active_profile": self.cfg.active_profile,
        })

    def handle_config_file(self, name):
        data = getattr(self.cfg, name, {})
        self.send_json(data)

    def handle_config_reload(self):
        self.cfg.reload()
        ReconHandler.tool_status = detect_tools(self.cfg)
        self.send_json({"ok": True, "message": "config reloaded"})

    def handle_tools(self):
        self.send_json({"tools": self.tool_status})

    def handle_get_profile(self):
        self.send_json({
            "active": self.cfg.active_profile,
            "values": self.cfg.get_profile_values(),
            "available": list(self.cfg.profiles.get("profiles", {}).keys()),
            "nuclei_defaults": self.cfg.get_nuclei_defaults(),
        })

    def handle_set_profile(self):
        body = self.read_body_json()
        if not body:
            return
        name = body.get("profile", "")
        available = self.cfg.profiles.get("profiles", {})
        if name not in available:
            self.send_json({"error": f"unknown profile: {name}"}, 400)
            return
        self.cfg.active_profile = name
        self.send_json({
            "active": name,
            "values": self.cfg.get_profile_values(name),
        })

    def handle_list_scans(self):
        cursor = self.db.execute(
            "SELECT id, target, target_type, round, profile, started_at, status "
            "FROM scans ORDER BY id DESC LIMIT 50"
        )
        rows = [dict(r) for r in cursor.fetchall()]
        self.send_json({"scans": rows})

    def handle_stats(self):
        counts = {}
        for table in ("scans", "subdomains", "hosts", "urls", "params", "findings"):
            row = self.db.execute(f"SELECT COUNT(*) as c FROM {table}").fetchone()
            counts[table] = row["c"]
        self.send_json({"counts": counts})

    def handle_run_tool(self):
        """POST /api/run — run a single tool in a background thread."""
        global runner
        body = self.read_body_json()
        if not body:
            return
        tool_name = body.get("tool", "")
        target = body.get("target", "")
        target_type = body.get("target_type", "wildcard")

        if not tool_name or not target:
            self.send_json({"error": "tool and target required"}, 400)
            return

        # Check tool availability
        status = self.tool_status.get(tool_name, {})
        if not status.get("available"):
            self.send_json({"error": f"{tool_name}: binary not found"}, 400)
            return

        spec = self.cfg.get_tool_spec(tool_name)
        if not spec:
            self.send_json({"error": f"unknown tool: {tool_name}"}, 400)
            return
        if not spec.get("enabled", True):
            self.send_json({"error": f"{tool_name}: disabled"}, 400)
            return

        # Create scan record
        with _db_lock:
            cursor = self.db.execute(
                "INSERT INTO scans (target, target_type, profile, status) VALUES (?,?,?,?)",
                (target, target_type, self.cfg.active_profile, "running"))
            self.db.commit()
            scan_id = cursor.lastrowid

        # Build context for template substitution
        context = body.get("context", {})
        context.setdefault("target", target)
        context.setdefault("host", target)
        context.setdefault("url", target)

        # Run in background thread
        def run():
            global runner
            try:
                runner.run_tool(tool_name, context, scan_id=scan_id)
            finally:
                with _db_lock:
                    self.db.execute("UPDATE scans SET status='done' WHERE id=?", (scan_id,))
                    self.db.commit()

        t = threading.Thread(target=run, daemon=True)
        t.start()

        self.send_json({"ok": True, "scan_id": scan_id, "tool": tool_name, "target": target})

    def handle_run_pipeline(self):
        """POST /api/pipeline — run a multi-step pipeline in background."""
        global runner, pipeline_runner
        body = self.read_body_json()
        if not body:
            return
        target = body.get("target", "")
        target_type = body.get("target_type", "wildcard")
        pipeline_name = body.get("pipeline", "r1")

        if not target:
            self.send_json({"error": "target required"}, 400)
            return

        # Build pipeline steps
        pipeline_map = {
            "r1": (build_r1_steps, 1),
            "r2": (build_r2_steps, 2),
            "r3": (build_r3_steps, 3),
            "wildcard": (build_wildcard_steps, 0),
        }
        entry = pipeline_map.get(pipeline_name)
        if not entry:
            self.send_json({"error": f"unknown pipeline: {pipeline_name}"}, 400)
            return
        build_fn, round_num = entry

        # Check dns wordlist for R2/wildcard
        if pipeline_name in ("r2", "wildcard"):
            dns_wl = runner._resolve_dns_wordlist()
            if not dns_wl and pipeline_name == "r2":
                self.send_json({"error": "No DNS wordlist found. Set dns_wordlist in config/paths.json"}, 400)
                return

        # Create scan record
        with _db_lock:
            cursor = self.db.execute(
                "INSERT INTO scans (target, target_type, round, profile, status) VALUES (?,?,?,?,?)",
                (target, target_type, round_num, self.cfg.active_profile, "running"))
            self.db.commit()
            scan_id = cursor.lastrowid

        steps = build_fn(scan_id)

        def run():
            try:
                pipeline_runner.run_pipeline(steps, target, target_type, scan_id)
            finally:
                with _db_lock:
                    self.db.execute("UPDATE scans SET status='done' WHERE id=?", (scan_id,))
                    self.db.commit()

        t = threading.Thread(target=run, daemon=True)
        t.start()

        step_labels = [s["label"] for s in steps]
        self.send_json({
            "ok": True, "scan_id": scan_id, "pipeline": pipeline_name,
            "target": target, "steps": step_labels,
        })

    def handle_stop_tool(self):
        """POST /api/stop — stop the currently running tool."""
        global runner
        if runner:
            runner.stop()
        self.send_json({"ok": True, "message": "stop signal sent"})

    def handle_subdomains(self):
        """GET /api/subdomains — return all subdomains."""
        with _db_lock:
            rows = self.db.execute(
                "SELECT fqdn, resolved_ip, sources, scan_id, created_at "
                "FROM subdomains ORDER BY fqdn"
            ).fetchall()
        self.send_json({"subdomains": [dict(r) for r in rows], "count": len(rows)})

    def handle_urls(self):
        """GET /api/urls — return all discovered URLs with metadata."""
        with _db_lock:
            rows = self.db.execute(
                "SELECT url, status_code, title, tech, server, tls_state, "
                "missing_headers, endpoint_count, screenshot_path, roi_score, "
                "promoted_to_target, sources, scan_id, created_at "
                "FROM urls ORDER BY roi_score DESC, url"
            ).fetchall()
        self.send_json({"urls": [dict(r) for r in rows], "count": len(rows)})

    def handle_screenshots_list(self):
        """GET /api/screenshots — list available screenshots."""
        ss_dir = self._get_screenshots_dir()
        ss_root = ss_dir / "screenshot"
        if not ss_root.is_dir():
            self.send_json({"screenshots": [], "count": 0})
            return
        files = []
        for f in ss_root.rglob("*.png"):
            # Relative path from screenshot/ dir = host/hash.png
            rel = f.relative_to(ss_root)
            files.append({
                "filename": f.name,
                "host": rel.parent.name,
                "path": str(rel),
                "url": f"/screenshots/{rel}",
                "size": f.stat().st_size,
            })
        files.sort(key=lambda x: x["host"])
        self.send_json({"screenshots": files, "count": len(files)})

    def handle_serve_screenshot(self, path):
        """Serve a screenshot image from the screenshots directory."""
        rel_path = path.split("/screenshots/", 1)[-1]
        # Sanitize — prevent path traversal
        if ".." in rel_path or rel_path.startswith("/"):
            self.send_json({"error": "invalid path"}, 400)
            return
        ss_dir = self._get_screenshots_dir()
        # httpx stores screenshots under <srd>/screenshot/<host>/<hash>.png
        filepath = ss_dir / "screenshot" / rel_path
        if not filepath.is_file():
            # Fallback: check directly in screenshots dir
            filepath = ss_dir / rel_path
        if not filepath.is_file():
            self.send_json({"error": "not found"}, 404)
            return
        # Verify the resolved path is still under ss_dir (no symlink escape)
        try:
            filepath.resolve().relative_to(ss_dir.resolve())
        except ValueError:
            self.send_json({"error": "invalid path"}, 403)
            return
        ext = filepath.suffix.lower()
        ct = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}.get(
            ext, "application/octet-stream")
        data = filepath.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(data)

    def _get_screenshots_dir(self):
        configured = self.cfg.paths.get("screenshots_dir", "")
        if configured:
            return Path(configured)
        return SCRIPT_DIR / "data" / "screenshots"

    def handle_sse(self):
        """GET /api/events — Server-Sent Events stream."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        q = event_bus.subscribe()
        try:
            # Send initial heartbeat
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()

            while True:
                try:
                    msg = q.get(timeout=15)
                    event = msg["event"]
                    data = json.dumps(msg["data"])
                    self.wfile.write(f"event: {event}\ndata: {data}\n\n".encode())
                    self.wfile.flush()
                except Empty:
                    # Send keepalive
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            event_bus.unsubscribe(q)

    # --- Helpers -----------------------------------------------------------

    def read_body_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            return json.loads(raw)
        except (ValueError, json.JSONDecodeError):
            self.send_json({"error": "invalid JSON body"}, 400)
            return None

    def send_json(self, data, status=200):
        payload = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        print(f"[recon-runner] {self.address_string()} {fmt % args}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global runner, pipeline_runner

    parser = argparse.ArgumentParser(description="recon-runner server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8777)
    args = parser.parse_args()

    # Load config
    cfg = Config()
    print(f"[recon-runner] config loaded (profile: {cfg.active_profile})")

    # Detect tools
    tool_status = detect_tools(cfg)
    found = sum(1 for t in tool_status.values() if t["available"])
    total = len(tool_status)
    print(f"[recon-runner] tools: {found}/{total} available")

    # Init DB
    db_path = cfg.paths.get("db_path", str(SCRIPT_DIR / "data" / "recon.db"))
    db = init_db(db_path)
    print(f"[recon-runner] database: {db_path}")

    # Create runners
    runner = ToolRunner(cfg, db, tool_status)
    pipeline_runner = PipelineRunner(runner)

    # Inject into handler class
    ReconHandler.cfg = cfg
    ReconHandler.db = db
    ReconHandler.tool_status = tool_status

    server = ThreadedHTTPServer((args.host, args.port), ReconHandler)
    print(f"[recon-runner] listening on http://{args.host}:{args.port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[recon-runner] shutting down")
        runner.stop()
        db.close()
        server.shutdown()


if __name__ == "__main__":
    main()
