"""Test-only EVE-NG and GNS3 REST API servers implementing the endpoints NetGuard reads.

The JSON shapes follow the public EVE-NG (unetlab) and GNS3 v2 APIs; they are small enough to keep in memory.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit


class _Server:
    def __init__(self, handler):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def eve_ng(lab: dict, username="admin", password="eve") -> _Server:
    """lab = {"path": "/Folder/lab.unl", "name": ..., "nodes": {id: {...}}, "interfaces": {id: [...]},
    "networks": {id: {...}}, "configs": {id: text}}"""
    sessions = set()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code, body, cookie=None):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            if cookie:
                self.send_header("Set-Cookie", f"unetlab_session={cookie}; Path=/")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authed(self):
            cookie = self.headers.get("Cookie", "")
            return any(f"unetlab_session={s}" in cookie for s in sessions)

        def do_POST(self):
            if self.path == "/api/auth/login":
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                if body.get("username") == username and body.get("password") == password:
                    sessions.add("s1")
                    return self._send(200, {"code": 200, "status": "success", "message": "User logged in (90013)."}, "s1")
                return self._send(400, {"code": 400, "status": "fail", "message": "Authentication failed (90012)."})
            self._send(404, {"code": 404})

        def do_GET(self):
            if not self._authed():
                return self._send(412, {"code": 412, "status": "unauthorized", "message": "User is not authenticated"})
            path = unquote(urlsplit(self.path).path)
            folder, _, name = lab["path"].rpartition("/")
            if path.startswith("/api/folders"):
                requested = path[len("/api/folders"):] or "/"
                if requested.rstrip("/") in ("", "/"):
                    return self._send(200, {"code": 200, "data": {"folders": [{"name": folder.strip("/"), "path": folder}],
                                                                 "labs": []}})
                if requested.rstrip("/") == folder:
                    return self._send(200, {"code": 200, "data": {"folders": [{"name": "..", "path": "/"}],
                                                                 "labs": [{"file": name, "path": lab["path"]}]}})
                return self._send(404, {"code": 404})
            base = "/api/labs" + lab["path"]
            if path == base:
                return self._send(200, {"code": 200, "data": {"name": lab["name"], "filename": name}})
            if path == base + "/nodes":
                return self._send(200, {"code": 200, "data": lab["nodes"]})
            if path == base + "/networks":
                return self._send(200, {"code": 200, "data": lab["networks"]})
            if path.startswith(base + "/nodes/") and path.endswith("/interfaces"):
                node = path[len(base + "/nodes/"):].split("/")[0]
                return self._send(200, {"code": 200, "data": {"ethernet": lab["interfaces"].get(node, []), "serial": []}})
            if path.startswith(base + "/configs/"):
                node = path.rsplit("/", 1)[1]
                if node in lab.get("configs", {}):
                    return self._send(200, {"code": 200, "data": {"id": node, "data": lab["configs"][node]}})
                return self._send(404, {"code": 404})
            self._send(404, {"code": 404})

    return _Server(Handler)


def gns3(project: dict) -> _Server:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = urlsplit(self.path).path
            pid = project["project_id"]
            if path == "/v2/version":
                return self._send(200, {"version": "2.2.49", "local": True})
            if path == "/v2/projects":
                return self._send(200, [{"name": project["name"], "project_id": pid, "status": project.get("status", "opened")}])
            if path == f"/v2/projects/{pid}/nodes":
                return self._send(200, project["nodes"])
            if path == f"/v2/projects/{pid}/links":
                return self._send(200, project["links"])
            self._send(404, {"message": "not found"})

        def do_POST(self):
            if self.path.endswith("/open"):
                project["status"] = "opened"
                return self._send(201, {"status": "opened"})
            self._send(404, {})

    return _Server(Handler)
