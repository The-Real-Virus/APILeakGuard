"""Project-owned local fixture with ordinary functional endpoints."""
import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Thread
from time import sleep
from urllib.parse import urlsplit

from apileakguard.reports import atomic_write


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_GET(self):
        route = urlsplit(self.path).path
        base = self.server.base
        role = self.headers.get("Authorization", "")
        cookie = self.headers.get("Cookie", "")
        self.server.calls.append((route, role, cookie))
        if route == "/v1/customer":
            self.reply(200, {"customer": {"id": "demo-1", "taxId": "999-99-0000"},
                             "next": f"{base}/v1/next"}, {"Cache-Control": "public, max-age=60"})
        elif route == "/v1/next":
            self.reply(200, {"ready": True})
        elif route == "/v1/session":
            if role not in {"Bearer synthetic-support", "Bearer synthetic-admin"}:
                self.reply(401, {"message": "Expected an active fixture session."})
                return
            label = role.rsplit("-", 1)[-1]
            self.reply(200, {"role": label, "cookie_matched": cookie == f"sessionid=fixture-{label}"},
                       {"Set-Cookie": f"sessionid=fixture-{label}; Path=/v1; HttpOnly"})
        elif route == "/v1/jump":
            self.reply(302, {"message": "External destination is a candidate only."},
                       {"Location": self.server.redirect_target})
        elif route == "/v1/slow":
            sleep(2.2)
            self.reply(200, {"ready": True})
        else:
            self.reply(404, {"message": "Fixture endpoint unavailable."})

    def reply(self, status, body, headers=None):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (ConnectionError, OSError):
            pass


def listener(port=0):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.base = f"http://127.0.0.1:{server.server_port}"
    server.calls = []
    server.redirect_target = f"{server.base}/v1/next"
    return server


@contextmanager
def fixture_pair(ports=(0, 0)):
    first, second = [listener(port) for port in ports]
    first.redirect_target = second.base + "/v1/next"
    threads = [Thread(target=server.serve_forever, daemon=True) for server in (first, second)]
    for thread in threads:
        thread.start()
    try:
        yield first, second
    finally:
        for server in (first, second):
            server.shutdown()
            server.server_close()


def make_operation(server, route, *, api="Support fixture", **values):
    return {"api": api, "base": server.base + "/v1", "path": route, "method": "GET",
            "environment": "test", "expect": {"status": 200, "content_type": "application/json"}, **values}


def make_suite(first, second):
    return {"schema_version": 1, "operations": [make_operation(first, "/v1/customer", role="support"),
            make_operation(second, "/v1/next", api="Independent fixture")]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ports", type=int, nargs=2, default=(0, 0))
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    with fixture_pair(options.ports) as (first, second):
        suite = make_suite(first, second)
        slow = {"schema_version": 1, "operations": [make_operation(first, "/v1/slow") for _ in range(5)]}
        for name, value in (("suite.json", suite), ("slow-suite.json", slow)):
            atomic_write(options.output / name, json.dumps(value, indent=2) + "\n", replace=True)
        atomic_write(options.output / "fixture-origins.json", json.dumps([first.base, second.base]), replace=True)
        print("Fixtures ready at", first.base, second.base, flush=True)
        try:
            while True:
                sleep(1)
        except KeyboardInterrupt:
            return


if __name__ == "__main__":
    main()
