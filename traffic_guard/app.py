"""应用装配：核心引擎 + HTTP 控制台 + 独立窗口 + 托盘 + 弹窗。"""
from __future__ import annotations

import json
import queue
import secrets
import signal
import threading
import time
from typing import Any, Dict, Optional

from .alerts import PopupManager
from .config import DATA_DIR, load_config
from .core import VERSION, Guard
from .server import ApiServer
from .window import open_window

SESSION_FILE = DATA_DIR / "session.json"


class Application:
    def __init__(self, no_elevate: bool = False, no_window: bool = False):
        self.cfg = load_config()
        self.no_window = no_window
        self.popup_q: queue.Queue = queue.Queue()
        self.guard = Guard(self.popup_q)
        self.token = secrets.token_urlsafe(18)
        self.server: Optional[ApiServer] = None
        self.popup: Optional[PopupManager] = None
        self.tray = None
        self._stopped = False
        self._window_opened = False

    # ------------------------------------------------------------ 窗口
    def open_console(self) -> bool:
        if not self.server:
            return False
        ui = self.cfg.get("ui", {})
        ok = open_window(
            self.server.url,
            DATA_DIR / "webview",
            (int(ui.get("window_width", 1400)), int(ui.get("window_height", 900))),
        )
        self._window_opened = True
        return ok

    # ------------------------------------------------------------ 决策回调
    def _on_decide(self, alert_id: str, decision: str, auto: bool = False) -> None:
        res = self.guard.decide(alert_id, decision)
        if not res.get("ok"):
            self.guard.log.warning("处理决策失败: %s", res.get("error"))
        elif auto:
            self.guard.log.info("提醒超时未响应，已默认保持断开")

    # ------------------------------------------------------------ 生命周期
    def run(self) -> int:
        port = int(self.cfg["server"]["port"])
        try:
            self.server = ApiServer(self.guard, self.token)
        except OSError:
            print(f"[警告] 端口 {port} 已被占用，可能已有实例在运行")
            return 2

        self.guard.shutdown_event = threading.Event()
        self.guard.on_shutdown = self._request_stop
        self.server.start()
        self.guard.start()
        self._write_session()
        self.guard.log.info("流量哨兵 %s 已启动，控制台：%s", VERSION, self.server.url)

        if not self.no_window and self.cfg["ui"].get("open_window", True):
            threading.Timer(0.8, self.open_console).start()
        elif self.cfg["server"].get("open_browser", True):
            threading.Timer(1.0, self.server.open_browser).start()

        if self.cfg["ui"].get("tray", True):
            try:
                from . import tray
                self.tray = tray.create(self.guard, self.open_console, self._request_stop)
            except Exception as exc:  # noqa: BLE001
                self.guard.log.warning("托盘图标不可用：%s", exc)

        self.popup = PopupManager(self.popup_q, self._on_decide)

        def _on_start() -> None:
            if not self.guard.geo.available and self.cfg["geoip"].get("auto_download", True):
                threading.Thread(target=self._download_geo, daemon=True).start()
            if not self.guard.admin:
                self.guard.log.warning("当前非管理员权限：可以监控，但无法自动截流")
                self.popup_q.put({
                    "kind": "notice", "id": "admin-warning",
                    "title": "未获得管理员权限",
                    "lines": [
                        "当前只能监控，无法写入防火墙规则。",
                        "请关闭后右键「以管理员身份运行」重启本程序。",
                    ],
                    "primary": "知道了", "secondary": None,
                })

        def _watch_stop() -> None:
            if self.guard.shutdown_event.is_set():
                self._stop_all()
                return
            if self.popup and self.popup.root:
                self.popup.root.after(400, _watch_stop)

        self.popup.run(on_start=lambda: (_on_start(), _watch_stop()))

        self._stop_all()
        return 0

    def _download_geo(self) -> None:
        """首次运行缺少 IP 库时后台自动下载。"""
        self.guard.log.info("未找到 GeoIP 数据库，开始自动下载……")
        res = self.guard.update_geoip()
        if res.get("ok"):
            self.guard.log.info("GeoIP 数据库已就绪（%s 字节）", res.get("size"))
        else:
            self.guard.log.warning("GeoIP 自动下载失败：%s", res.get("error"))

    def _request_stop(self) -> None:
        if self.guard.shutdown_event:
            self.guard.shutdown_event.set()

    def _stop_all(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        for closer in (lambda: self.tray and self.tray.stop(),
                       self.guard.stop,
                       lambda: self.server and self.server.stop()):
            try:
                closer()
            except Exception:  # noqa: BLE001
                pass
        try:
            SESSION_FILE.unlink(missing_ok=True)
        except OSError:
            pass
        if self.popup and self.popup.root:
            try:
                self.popup.root.quit()
            except Exception:  # noqa: BLE001
                pass

    def _write_session(self) -> None:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            SESSION_FILE.write_text(json.dumps({
                "pid": __import__("os").getpid(),
                "port": self.server.port if self.server else 0,
                "host": self.cfg["server"]["host"],
                "token": self.token,
                "url": self.server.url if self.server else "",
                "started": time.time(),
                "admin": self.guard.admin,
                "version": VERSION,
            }, ensure_ascii=False), encoding="utf-8")
        except OSError as exc:
            self.guard.log.warning("写入会话文件失败: %s", exc)


def main(argv: list[str]) -> int:
    app = Application(no_window="--no-window" in argv)

    def _sig(_signum, _frame):
        app._request_stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _sig)
        except (ValueError, OSError):
            pass
    return app.run()
