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
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
WEB_DIR = SCRIPT_DIR / "web"

# Lazy import — doctor is in the same directory
import doctor


class ReconHandler(SimpleHTTPRequestHandler):
    """HTTP handler: serves web/ for static files, /api/* for endpoints."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_GET(self):
        if self.path == "/api/doctor":
            self.handle_doctor()
        else:
            super().do_GET()

    def handle_doctor(self):
        results = doctor.run_checks()
        body = doctor.results_to_dict(results)
        self.send_json(body)

    def send_json(self, data, status=200):
        payload = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        # Prefix with [recon-runner] for clarity
        print(f"[recon-runner] {self.address_string()} {format % args}")


def main():
    parser = argparse.ArgumentParser(description="recon-runner server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8777)
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), ReconHandler)
    print(f"[recon-runner] listening on http://{args.host}:{args.port}")
    print(f"[recon-runner] doctor endpoint: http://{args.host}:{args.port}/api/doctor")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[recon-runner] shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
