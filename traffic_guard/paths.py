"""路径解析：区分「只读资源目录」与「可写数据目录」。

* 源码运行：资源=项目根目录，数据=项目根目录/data
* 单文件 exe：资源=解包临时目录(sys._MEIPASS)，数据=%LOCALAPPDATA%\\TrafficGuard
* 便携模式（exe 同目录存在 portable.flag 或命令行 --portable）：数据=exe 同目录/data
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resource_dir() -> Path:
    """只读资源（web 页面、内置 IP 库）所在目录。"""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent


def app_dir() -> Path:
    """程序（exe）所在目录；源码运行时为项目根目录。"""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    """可写数据目录：配置、SQLite、日志、IP 库、浏览器配置。

    * 源码运行：项目根目录/data（与 1.x 一致，方便调试）
    * 打包 exe：%LOCALAPPDATA%\\TrafficGuard（免安装、每个用户独立）
    * 便携模式：程序目录/data
    """
    if portable_mode():
        path = app_dir() / "data"
    elif not is_frozen():
        path = app_dir() / "data"
    else:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
        path = Path(base) / "TrafficGuard"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        path = app_dir() / "data"
        path.mkdir(parents=True, exist_ok=True)
    return path


def portable_mode() -> bool:
    try:
        if "--portable" in sys.argv:
            return True
        return (app_dir() / "portable.flag").exists()
    except Exception:  # noqa: BLE001
        return False


def bundled_geoip() -> Optional[Path]:
    """打包内置的 IP 库（首次运行会复制到数据目录）。"""
    p = resource_dir() / "data" / "GeoLite2-Country.mmdb"
    return p if p.exists() else None


def ensure_geoip(target: Path) -> Path:
    """确保数据目录里有 IP 库；没有就从内置资源复制。"""
    if target.exists() and target.stat().st_size > 1_000_000:
        return target
    src = bundled_geoip()
    if src is not None:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(src.read_bytes())
            return target
        except OSError:
            return target
    return target
