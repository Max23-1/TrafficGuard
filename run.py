"""启动入口：自动申请管理员权限 → 启动监控 → 打开独立控制台窗口。

用法：
    python run.py                # 自动提权启动（推荐）
    python run.py --no-window    # 不打开窗口，只托盘 + 弹窗
    python run.py --browser      # 用系统默认浏览器打开，而不是独立窗口
    python run.py --portable     # 数据写在程序目录（U盘/绿色版）
    python run.py --no-elevate   # 不提权，仅监控（无法自动截流）
    python run.py --check        # 自检：环境 / 依赖 / GeoIP / 权限
"""
from __future__ import annotations

import ctypes
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# 控制台默认可能是 GBK（cmd），统一成 UTF-8 并容错
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass

VERSION = "2.1.0"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _pythonw() -> str:
    if is_frozen():
        return sys.executable
    exe = Path(sys.executable)
    cand = exe.with_name("pythonw.exe")
    return str(cand) if cand.exists() else str(exe)


def elevate(extra: list[str]) -> bool:
    from traffic_guard.paths import app_dir
    if is_frozen():
        target = sys.executable
        params = subprocess.list2cmdline(extra + ["--elevated"])
    else:
        target = _pythonw()
        params = subprocess.list2cmdline([str(app_dir() / "run.py"), "--elevated"] + extra)
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", target, params,
                                                  str(app_dir()), 1)
        return int(ret) > 32
    except Exception:  # noqa: BLE001
        return False


def check() -> int:
    from traffic_guard import winapi as W
    from traffic_guard.config import DATA_DIR, load_config, resolve_path
    from traffic_guard.geoip import GeoResolver
    from traffic_guard.paths import app_dir, is_frozen as _frozen, portable_mode

    cfg = load_config()
    print(f"== 流量哨兵 {VERSION} 自检 ==")
    print(f"运行方式    : {'打包 exe' if _frozen() else '源码'}（{app_dir()}）")
    print(f"数据目录    : {DATA_DIR}{'（便携模式）' if portable_mode() else ''}")
    print(f"Python      : {sys.version.split()[0]}  ({sys.executable})")
    print(f"管理员权限  : {'是' if W.is_admin() else '否（无法自动截流）'}")
    print(f"防火墙服务  : {'正常' if W.firewall_available() else '异常'}")
    try:
        c = W.tcp_connections(include_listen=False)
        print(f"TCP 连接表  : {len(c)} 条")
    except Exception as exc:  # noqa: BLE001
        print(f"TCP 连接表  : 读取失败 {exc}")
    try:
        s = W.interface_stats()
        print(f"网卡统计    : {len(s['adapters'])} 个活动网卡，累计 ↓{s['rx'] / 1e9:.2f} GB ↑{s['tx'] / 1e9:.2f} GB")
    except Exception as exc:  # noqa: BLE001
        print(f"网卡统计    : 读取失败 {exc}")
    geo = GeoResolver(resolve_path(cfg["geoip"]["db_path"]),
                      home_country=cfg["policy"]["home_country"])
    if geo.available:
        print(f"GeoIP 数据库: {geo.db_path}（{geo.reader.database_type}）")
        for ip in ("8.8.8.8", "114.114.114.114"):
            r = geo.lookup(ip)
            print(f"  {ip:16s} -> {r['country_cn']} ({r['scope']})")
    else:
        print(f"GeoIP 数据库: 不可用 {geo.error}")
    try:
        import pystray  # noqa: F401
        print("托盘支持    : 可用")
    except Exception:  # noqa: BLE001
        print("托盘支持    : 不可用（不影响主功能）")
    print(f"控制台地址  : http://{cfg['server']['host']}:{cfg['server']['port']}/")
    return 0


def open_existing() -> bool:
    """已有实例在运行：唤起它的独立窗口。"""
    from traffic_guard.config import DATA_DIR, load_config, resolve_path
    cfg = load_config()
    url = f"http://{cfg['server']['host']}:{int(cfg['server']['port'])}/"
    try:
        session = json.loads((DATA_DIR / "session.json").read_text(encoding="utf-8"))
        url = session.get("url") or url
    except Exception:  # noqa: BLE001
        pass
    try:
        from traffic_guard.window import open_window
        if open_window(url, DATA_DIR / "webview"):
            return True
    except Exception:  # noqa: BLE001
        pass
    import webbrowser
    webbrowser.open(url)
    return True


def main() -> int:
    argv = sys.argv[1:]
    if "--check" in argv or "--version" in argv:
        if "--version" in argv and "--check" not in argv:
            print(VERSION)
            return 0
        return check()

    elevated = "--elevated" in argv
    no_elevate = "--no-elevate" in argv

    if not is_admin() and not elevated and not no_elevate:
        print("正在申请管理员权限（截流需要写入防火墙规则）……")
        if elevate([a for a in argv if a not in ("--elevated",)]):
            print("已在新进程中以管理员身份启动。")
            return 0
        print("[警告] 未获得管理员权限，将以「仅监控」模式运行：可以查看流量与风险，但无法自动截流。")

    from traffic_guard.config import load_config
    from traffic_guard.server import port_in_use
    cfg = load_config()
    host, port = cfg["server"]["host"], int(cfg["server"]["port"])
    if port_in_use(host, port):
        print(f"检测到已有实例在运行，正在唤起控制台窗口：{host}:{port}")
        open_existing()
        time.sleep(0.5)
        return 0

    from traffic_guard.app import main as app_main
    return app_main(argv)


if __name__ == "__main__":
    sys.exit(main())

