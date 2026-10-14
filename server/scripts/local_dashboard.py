"""Open this folder's dashboard on this computer.

    python scripts/local_dashboard.py [--url http://127.0.0.1:8000]

The `bsecured` CLI has no dashboard command yet, so this is how the dashboard is
opened. It serves the dashboard page on 127.0.0.1 only, opens your browser, and
gives the page the server address and this folder's .bsecured/dashboard_key
through /config.json. The key never appears in a link. Ctrl+C to stop.
"""

from __future__ import annotations

import argparse
import http.server
import json
import pathlib
import socketserver
import sys
import webbrowser

PAGE = pathlib.Path(__file__).resolve().parents[2] / "dashboard" / "index.html"


class LoopbackServer(http.server.HTTPServer):
    def server_bind(self) -> None:
        # HTTPServer normally reverse-resolves the bind address here, before it
        # starts listening. That lookup can stall for many seconds, and the name is
        # never used, so it is skipped.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        # Refuse any Host but our own address. Otherwise a web page that rebinds
        # its domain name to 127.0.0.1 could read /config.json and take the key.
        if self.headers.get("Host") not in self.server.allowed_hosts:
            self.send_error(403)
            return
        if self.path == "/":
            body, content_type = PAGE.read_bytes(), "text/html; charset=utf-8"
        elif self.path == "/config.json":
            body, content_type = json.dumps(self.server.config).encode(), "application/json"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass  # keep the terminal quiet


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="the bSecured server")
    parser.add_argument("--port", type=int, default=0, help="local port; 0 picks a free one")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    key_file = pathlib.Path(".bsecured/dashboard_key")
    if not key_file.exists():
        sys.exit("No .bsecured/dashboard_key in this folder. Run `scripts/devices.py register` here first.")

    httpd = LoopbackServer(("127.0.0.1", args.port), DashboardHandler)
    port = httpd.server_address[1]
    httpd.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    httpd.config = {"server_url": args.url.rstrip("/"), "dashboard_key": key_file.read_text().strip()}

    page = f"http://127.0.0.1:{port}/"
    print(f"dashboard: {page}   (Ctrl+C to stop)", flush=True)
    if not args.no_browser:
        webbrowser.open(page)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
