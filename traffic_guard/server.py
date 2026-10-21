"""本机 HTTP 控制台（127.0.0.1）：仪表盘 + JSON API。"""
from __future__ import annotations

import json
import mimetypes
import posixpath
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from .config import ROOT, load_config

WEB_DIR = ROOT / "web"


class ApiHandler(BaseHTTPRequestHandler):
    guard = None          # type: ignore[assignment]
    token: str = ""
    server_version = "TrafficGuard/1.0"

    # ------------------------------------------------------------ 基础工具
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return

    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8",
              extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, data: Any, code: int = 200) -> None:
        self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def _read_json(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if length <= 0 or length > 2_000_000:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:  # noqa: BLE001
            return {}

    def _authorized(self) -> bool:
        tok = self.headers.get("X-TG-Token") or ""
        return bool(self.token) and tok == self.token

    @staticmethod
    def _same_origin() -> bool:
        return True

    # ------------------------------------------------------------ 路由
    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path in ("/", "/index.html"):
            return self._serve_index()
        if path.startswith("/static/"):
            return self._serve_static(path[len("/static/"):])
        if path.startswith("/api/"):
            return self._api_get(path, urllib.parse.parse_qs(parsed.query))
        return self._send(404, b'{"error":"not found"}')

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if not path.startswith("/api/"):
            return self._send(404, b'{"error":"not found"}')
        if not self._authorized():
            return self._json({"ok": False, "error": "无效的访问令牌"}, 403)
        body = self._read_json()
        try:
            return self._api_post(path, body)
        except Exception as exc:  # noqa: BLE001
            return self._json({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, 500)

    # ------------------------------------------------------------ 静态资源
    def _serve_index(self) -> None:
        idx = WEB_DIR / "index.html"
        if not idx.exists():
            return self._send(500, "缺少 web/index.html".encode("utf-8"), "text/plain; charset=utf-8")
        html = idx.read_text(encoding="utf-8").replace("__TG_TOKEN__", self.token)
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def _serve_static(self, rel: str) -> None:
        rel = urllib.parse.unquote(rel)
        safe = posixpath.normpath(rel).lstrip("/").replace("..", "")
        target = (WEB_DIR / safe).resolve()
        if not str(target).startswith(str(WEB_DIR.resolve())) or not target.is_file():
            return self._send(404, b'{"error":"not found"}')
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        self._send(200, target.read_bytes(), ctype)

    # ------------------------------------------------------------ GET API
    def _api_get(self, path: str, q: Dict[str, list]) -> None:
        g = self.guard
        if path == "/api/status":
            return self._json(g.status())
        if path == "/api/live":
            return self._json({
                "status": g.status(),
                "flows": g.flows_snapshot(limit=200, sort=(q.get("sort", ["risk"])[0])),
                "countries": g.countries_snapshot(),
                "processes": g.processes_snapshot()[:40],
                "ts": time.time(),
            })
        if path == "/api/flows":
            limit = int((q.get("limit", ["300"])[0]))
            sort = q.get("sort", ["risk"])[0]
            return self._json(g.flows_snapshot(limit=limit, sort=sort))
        if path == "/api/countries":
            return self._json(g.countries_snapshot())
        if path == "/api/processes":
            return self._json(g.processes_snapshot())
        if path == "/api/events":
            limit = int((q.get("limit", ["120"])[0]))
            return self._json(g.events_snapshot(limit=limit))
        if path == "/api/alerts":
            return self._json(g.status().get("alerts", []))
        if path == "/api/config":
            return self._json(g.config_snapshot())
        if path == "/api/geoip":
            return self._json(g.geo.info())
        return self._json({"error": "not found"}, 404)

    # ------------------------------------------------------------ POST API
    def _api_post(self, path: str, body: Dict[str, Any]) -> None:
        g = self.guard
        if path == "/api/decide":
            aid = str(body.get("id") or "")
            decision = str(body.get("decision") or "")
            return self._json(g.decide(aid, decision))
        if path == "/api/control":
            action = str(body.get("action") or "")
            return self._json(g.control(action, name=body.get("name"),
                                        reason=body.get("reason")))
        if path == "/api/config":
            patch = body.get("patch") or {}
            if not isinstance(patch, dict):
                return self._json({"ok": False, "error": "patch 必须是对象"}, 400)
            cfg = g.update_config(patch)
            return self._json({"ok": True, "config": cfg})
        if path == "/api/whitelist":
            kind = str(body.get("kind") or "ip")
            value = str(body.get("value") or "").strip()
            action = str(body.get("action") or "add")
            if not value:
                return self._json({"ok": False, "error": "值不能为空"}, 400)
            return self._json(g.whitelist(kind, value, action))
        if path == "/api/geoip/update":
            return self._json(g.update_geoip())
        return self._json({"ok": False, "error": "not found"}, 404)


class ApiServer:
    def __init__(self, guard, token: str):
        cfg = load_config()
        self.host = cfg["server"]["host"]
        self.port = int(cfg["server"]["port"])
        handler = type("BoundApiHandler", (ApiHandler,), {"guard": guard, "token": token})
        self.httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self.httpd.daemon_threads = True
        self.thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def start(self) -> None:
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="http", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:  # noqa: BLE001
            pass

    def open_browser(self) -> None:
        try:
            webbrowser.open(self.url)
        except Exception:  # noqa: BLE001
            pass


def port_in_use(host: str, port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return s.connect_ex((host, port)) == 0
