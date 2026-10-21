"""系统托盘图标（pystray，可选）：右键打开控制台 / 断流 / 退出。"""
from __future__ import annotations

import threading
from typing import Any, Callable, Optional


def _make_image(size: int = 64):
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((3, 3, size - 3, size - 3), radius=14, fill=(62, 142, 247, 255))
    d.ellipse((size * 0.28, size * 0.28, size * 0.72, size * 0.72), fill=(255, 255, 255, 255))
    d.ellipse((size * 0.40, size * 0.40, size * 0.60, size * 0.60), fill=(62, 142, 247, 255))
    return img


def create(guard: Any, on_open: Callable[[], None], on_exit: Callable[[], None],
           on_settings: Optional[Callable[[], None]] = None) -> Optional[Any]:
    """创建并显示托盘图标；失败时静默返回 None（不影响主功能）。"""
    try:
        import pystray
    except Exception:  # noqa: BLE001
        return None

    def open_window(_icon=None, _item=None) -> None:
        threading.Thread(target=on_open, daemon=True).start()

    def pending_text(_item) -> str:
        n = len(getattr(guard, "pending", {}) or {})
        return f"待处理提醒：{n} 条" if n else "暂无待处理提醒"

    def kill(_icon=None, _item=None) -> None:
        guard.control("kill_switch_on", reason="托盘手动断流")

    def restore(_icon=None, _item=None) -> None:
        guard.control("kill_switch_off")

    def quit_app(_icon=None, _item=None) -> None:
        try:
            icon.stop()
        except Exception:  # noqa: BLE001
            pass
        on_exit()

    menu = pystray.Menu(
        pystray.MenuItem("打开控制台", open_window, default=True),
        pystray.MenuItem(pending_text, None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("紧急断流（全部公网）", kill),
        pystray.MenuItem("恢复网络", restore),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("退出流量哨兵", quit_app),
    )
    try:
        icon = pystray.Icon("TrafficGuard", _make_image(64), "流量哨兵 · 本机流量与跨境风险", menu)
        icon.run_detached()
        return icon
    except Exception:  # noqa: BLE001
        return None
