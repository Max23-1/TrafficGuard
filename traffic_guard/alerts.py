"""弹窗提醒：置顶窗口。风险弹窗「先截流后告知」，由机主决定继续还是断开；通知类弹窗只做告知。"""
from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from tkinter import font as tkfont
from typing import Any, Dict, Optional

try:
    import winsound
except ImportError:  # pragma: no cover
    winsound = None

BG = "#14161d"
CARD = "#1b1e28"
FG = "#e8eaf0"
MUTED = "#9aa3b2"
RED = "#e5484d"
AMBER = "#f5a524"
GREEN = "#30a46c"
BLUE = "#3e8ef7"


def _fmt_bytes(n: float) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


class PopupWindow:
    def __init__(self, master: tk.Tk, data: Dict[str, Any], on_decide, on_close):
        self.data = data
        self.on_decide = on_decide
        self.on_close = on_close
        self.decided = False
        kind = str(data.get("kind") or "risk")
        self.is_notice = kind in ("notice", "quota")
        self.remaining = max(10, int(data.get("deadline", time.time() + 60) - time.time()))

        self.win = tk.Toplevel(master)
        self.win.title("流量哨兵 · 提醒" if self.is_notice else "流量哨兵 · 风险提醒")
        self.win.configure(bg=BG)
        self.win.attributes("-topmost", True)
        self.win.resizable(False, False)
        self.win.protocol("WM_DELETE_WINDOW", self._on_window_close)
        try:
            self.win.attributes("-alpha", 0.98)
        except tk.TclError:
            pass

        width, height = (520, 320) if self.is_notice else (560, 430)
        self.win.geometry(f"{width}x{height}+{self._x(width)}+{self._y(height)}")

        f_title = tkfont.Font(family="Microsoft YaHei UI", size=14, weight="bold")
        f_body = tkfont.Font(family="Microsoft YaHei UI", size=10)
        f_small = tkfont.Font(family="Microsoft YaHei UI", size=9)

        accent = AMBER if self.is_notice else RED
        head = tk.Frame(self.win, bg=accent, height=52)
        head.pack(fill="x")
        head.pack_propagate(False)
        head_text = data.get("title") or ("提醒" if self.is_notice
                                          else "已先截流：检测到高风险跨境/境外连接")
        tk.Label(head, text=("ⓘ  " if self.is_notice else "⚠  ") + head_text,
                 bg=accent, fg="#ffffff", font=f_title, wraplength=width - 36,
                 justify="left").pack(side="left", padx=18)

        body = tk.Frame(self.win, bg=BG)
        body.pack(fill="both", expand=True, padx=18, pady=14)

        btns = tk.Frame(self.win, bg=CARD)
        btns.pack(fill="x", side="bottom")
        inner = tk.Frame(btns, bg=CARD)
        inner.pack(fill="x", padx=14, pady=12)

        if self.is_notice:
            for idx, text in enumerate(data.get("lines") or []):
                tk.Label(body, text=text, bg=BG, fg=FG if idx == 0 else MUTED, font=f_body,
                         anchor="w", wraplength=width - 60, justify="left").pack(fill="x", pady=2)
            tk.Button(inner, text=data.get("primary") or "知道了",
                      command=lambda: self._decide("block"),
                      bg="#2c3242", fg=FG, activebackground="#3a4256", activeforeground=FG,
                      relief="flat", font=f_body, width=14, cursor="hand2").pack(side="right")
            tk.Button(inner, text="打开控制台", command=self._open_detail,
                      bg=BLUE, fg="white", activebackground="#2f7ae0", activeforeground="white",
                      relief="flat", font=f_body, width=14, cursor="hand2").pack(side="left")
            if winsound:
                try:
                    winsound.MessageBeep(winsound.MB_ICONASTERISK)
                except Exception:  # noqa: BLE001
                    pass
            return

        flow = data.get("flow") or {}
        risk = data.get("risk") or {}
        rows = [
            ("进程", f'{flow.get("process") or "未知"}（PID {flow.get("pid")}）'),
            ("应用", flow.get("app") or "未知应用"),
            ("远端", f'{flow.get("remote_ip")}:{flow.get("remote_port")}'),
            ("归属", f'{flow.get("country_cn") or "未知"}  ·  {self._scope_cn(flow.get("scope"))}'),
            ("风险", f'{risk.get("level_cn", "")}  {risk.get("score", 0)}/100'),
        ]
        for label, value in rows:
            row = tk.Frame(body, bg=BG)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label, bg=BG, fg=MUTED, font=f_body, width=5, anchor="w").pack(side="left")
            tk.Label(row, text=value, bg=BG, fg=FG, font=f_body, anchor="w",
                     wraplength=430, justify="left").pack(side="left")

        tk.Frame(body, bg="#2a2f3d", height=1).pack(fill="x", pady=8)
        tk.Label(body, text="判定依据", bg=BG, fg=MUTED, font=f_small, anchor="w").pack(fill="x")

        reasons = risk.get("reasons") or ["命中风险规则"]
        for r in reasons[:5]:
            tk.Label(body, text=f"· {r}", bg=BG, fg="#ffd7d7", font=f_body, anchor="w",
                     wraplength=505, justify="left").pack(fill="x", pady=1)

        block = data.get("block") or {}
        if block.get("ok"):
            note, color = "防火墙规则已生效，该连接已被实时阻断。", GREEN
        elif block.get("hint"):
            note, color = f'自动截流未生效：{block.get("hint")}', AMBER
        else:
            note, color = "截流状态未知，请手动确认。", AMBER
        tk.Label(body, text=note, bg=BG, fg=color, font=f_small, anchor="w",
                 wraplength=505, justify="left").pack(fill="x", pady=(10, 2))

        self.count_var = tk.StringVar()
        tk.Label(body, textvariable=self.count_var, bg=BG, fg=MUTED, font=f_small,
                 anchor="w").pack(fill="x", pady=(6, 0))

        tk.Button(inner, text="保持断开（推荐）", command=lambda: self._decide("block"),
                  bg=RED, fg="white", activebackground="#c93c41", activeforeground="white",
                  relief="flat", font=f_body, width=16, cursor="hand2").pack(side="left")
        tk.Button(inner, text="继续连接（解除拦截）", command=lambda: self._decide("continue"),
                  bg="#2c3242", fg=FG, activebackground="#3a4256", activeforeground=FG,
                  relief="flat", font=f_body, width=18, cursor="hand2").pack(side="left", padx=10)
        tk.Button(inner, text="详情", command=self._open_detail,
                  bg="#232836", fg=FG, activebackground="#2c3242", activeforeground=FG,
                  relief="flat", font=f_small, cursor="hand2").pack(side="right")

        if winsound:
            try:
                winsound.MessageBeep(winsound.MB_ICONHAND)
            except Exception:  # noqa: BLE001
                pass
        self._tick()

    @staticmethod
    def _scope_cn(scope: Optional[str]) -> str:
        return {"OVERSEAS": "境外", "HMT": "中国港澳台", "DOMESTIC": "中国大陆",
                "LAN": "局域网", "UNKNOWN": "归属未知"}.get(scope or "", "未知")

    def _x(self, w: int) -> int:
        return max(0, self.win.winfo_screenwidth() - w - 24)

    def _y(self, h: int) -> int:
        return max(0, self.win.winfo_screenheight() - h - 72)

    def _tick(self) -> None:
        if self.decided or self.is_notice:
            return
        self.remaining -= 1
        if self.remaining <= 0:
            self._decide("block", auto=True)
            return
        self.count_var.set(
            f"{self.remaining} 秒后自动保持断开（默认最安全）。倒计时内可随时选择继续连接。"
        )
        self.win.after(1000, self._tick)

    def _decide(self, decision: str, auto: bool = False) -> None:
        if self.decided:
            return
        self.decided = True
        try:
            self.win.destroy()
        except tk.TclError:
            pass
        # 通知类弹窗（权限告警、配额）没有「继续/断开」语义，直接关闭
        if self.is_notice:
            self.on_close(self)
            return
        threading.Thread(target=self.on_decide, args=(self.data.get("id"), decision, auto),
                         daemon=True).start()
        self.on_close(self)

    def _on_window_close(self) -> None:
        # 直接关窗 = 保持断开（不会解除拦截）
        self._decide("block")

    def _open_detail(self) -> None:
        try:
            from .config import load_config, DATA_DIR
            from .window import open_window
            cfg = load_config()
            open_window(f'http://{cfg["server"]["host"]}:{cfg["server"]["port"]}/',
                        DATA_DIR / "webview")
        except Exception:  # noqa: BLE001
            pass


class PopupManager:
    """在主线程运行 Tk 事件循环，串行展示提醒窗口。"""

    def __init__(self, popup_queue: queue.Queue, on_decide, on_ready=None):
        self.queue = popup_queue
        self.on_decide = on_decide
        self.on_ready = on_ready
        self.root: Optional[tk.Tk] = None
        self.active: Optional[PopupWindow] = None
        self._pending: list[Dict[str, Any]] = []
        self._stop = False

    def _handle(self, data: Dict[str, Any]) -> None:
        try:
            self.active = PopupWindow(self.root, data, self._decide, self._closed)
        except Exception:  # noqa: BLE001
            self.active = None

    def _decide(self, alert_id: str, decision: str, auto: bool) -> None:
        try:
            self.on_decide(alert_id, decision, auto)
        except Exception:  # noqa: BLE001
            pass

    def _closed(self, win: PopupWindow) -> None:
        self.active = None

    def _poll(self) -> None:
        if self._stop:
            return
        try:
            while True:
                data = self.queue.get_nowait()
                if self.active is None and not self._pending:
                    self._handle(data)
                else:
                    self._pending.append(data)
        except queue.Empty:
            pass
        if self.active is None and self._pending:
            self._handle(self._pending.pop(0))
        if self.root:
            self.root.after(300, self._poll)

    def run(self, on_start=None) -> None:
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title("流量哨兵")
        self.root.report_callback_exception = lambda *a: None
        self.root.after(300, self._poll)
        if on_start:
            try:
                on_start()
            except Exception:  # noqa: BLE001
                pass
        if self.on_ready:
            self.on_ready()
        self.root.mainloop()

    def stop(self) -> None:
        self._stop = True
        if self.root:
            try:
                self.root.quit()
            except tk.TclError:
                pass
