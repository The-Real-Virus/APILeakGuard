"""A first request against an isolated, short-lived loopback example."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Thread

from .requests import preview

PATH = "/customers/1"
BODY = json.dumps({"customer": {"id": "demo-1", "email": "customer@example.test"}}).encode("utf-8")


class PracticeHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path != PATH:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)


def practice_request(workspace, cancel, progress):
    with ThreadingHTTPServer(("127.0.0.1", 0), PracticeHandler) as server:
        thread = Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}/"
            suite = {"schema_version": 1, "operations": [
                {"api": "Practice API", "environment": "local demo", "method": "GET", "base": base,
                 "path": PATH, "expect": {"status": 200}}
            ]}
            workspace.approve(suite, preview(suite)["suite_fingerprint"])
            return workspace.run(suite, cancel=cancel, progress=progress)
        finally:
            server.shutdown()
            thread.join()
