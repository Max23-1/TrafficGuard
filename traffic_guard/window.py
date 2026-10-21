"""独立程序窗口：用 Edge/Chrome 的 --app 模式把控制台变成一个独立应用窗口。

没有安装 Edge/Chrome 时回退到系统默认浏览器（仍然是完整功能）。
"""
from __future__ import annotations

import os
import subprocess
import sys
import webbrowser
from pathlib import Path
from typing import Optional, Tuple

CANDIDATES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]

DETACHED_PROCESS = 0x00000008
CREATE_NO_WINDOW = 0x08000000


def find_browser() -> Optional[str]:
    for path in CANDIDATES:
        if Path(path).is_file():
            return path
    # 兜底：从注册表找默认浏览器
    try:
        import winreg
        for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(root, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe") as k:
                    val, _ = winreg.QueryValueEx(k, "")
                    if Path(val).is_file():
                        return val
            except OSError:
                continue
    except Exception:  # noqa: BLE001
        pass
    return None


def open_window(url: str, profile_dir: str | Path,
                size: Tuple[int, int] = (1400, 900)) -> bool:
    """打开独立窗口；返回是否使用了「应用窗口」模式。"""
    exe = find_browser()
    if not exe:
        webbrowser.open(url)
        return False
    profile = Path(profile_dir)
    try:
        profile.mkdir(parents=True, exist_ok=True)
    except OSError:
        profile = Path(os.environ.get("TEMP", ".")) / "TrafficGuard-profile"
    args = [
        exe,
        f"--app={url}",
        f"--window-size={size[0]},{size[1]}",
        f"--user-data-dir={profile}",
        "--no-first-run",
        "--no-default-browser-check",
        "--no-service-autorun",
        "--disable-background-mode",
        "--disable-sync",
        "--disable-features=Translate,MediaRouter,msEdgeSyncPromo,msImplicitSignin,"
        "EdgeCollections,msEdgeIdentity", 
        "--disable-component-update",
    ]
    try:
        subprocess.Popen(args, close_fds=True,
                         creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW)
        return True
    except OSError:
        webbrowser.open(url)
        return False


def open_folder(path: str | Path) -> None:
    try:
        os.startfile(str(path))  # noqa: S606
    except Exception:  # noqa: BLE001
        pass
