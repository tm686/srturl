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
import sqlite3
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

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


# ---------------------------------------------------------------------------
# Tool availability detection
# ---------------------------------------------------------------------------

def detect_tools(cfg):
    """Return dict of tool_name -> {available, path, enabled, optional, phase, target_types}."""
    bin_dir = cfg.get_bin_dir()
    registry = cfg.tools.get("tools", {})
    result = {}
    for name, spec in registry.items():
        binary = spec.get("binary", name)
        path = doctor.find_binary(binary, bin_dir)
        result[name] = {
            "available": path is not None,
            "path": path or "",
            "enabled": spec.get("enabled", True),
            "optional": spec.get("optional", False),
            "gated": spec.get("gated", False),
            "phase": spec.get("phase", ""),
            "target_types": spec.get("target_types", []),
        }
    return result


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
        qs = parse_qs(parsed.query)

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
        }

        handler = routes.get(path)
        if handler:
            handler()
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

    # Inject into handler class
    ReconHandler.cfg = cfg
    ReconHandler.db = db
    ReconHandler.tool_status = tool_status

    server = HTTPServer((args.host, args.port), ReconHandler)
    print(f"[recon-runner] listening on http://{args.host}:{args.port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[recon-runner] shutting down")
        db.close()
        server.shutdown()


if __name__ == "__main__":
    main()
