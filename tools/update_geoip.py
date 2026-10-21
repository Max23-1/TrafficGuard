"""下载 / 更新 GeoLite2-Country 离线数据库。

用法：
    python tools/update_geoip.py            # 下载到 data/GeoLite2-Country.mmdb
    python tools/update_geoip.py --check    # 只检查现有库
"""
from __future__ import annotations

import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from traffic_guard.config import load_config, resolve_path  # noqa: E402
from traffic_guard.geoip import GeoResolver  # noqa: E402


def main() -> int:
    cfg = load_config()
    target = resolve_path(cfg["geoip"]["db_path"])
    check_only = "--check" in sys.argv

    if target.exists():
        geo = GeoResolver(target)
        built = geo.reader.metadata.get("build_epoch") if geo.available else None
        when = time.strftime("%Y-%m-%d", time.localtime(built)) if built else "未知"
        print(f"现有数据库：{target}（{target.stat().st_size / 1e6:.2f} MB，构建于 {when}）")
        if not geo.available:
            print(f"  ⚠ 加载失败：{geo.error}")
    else:
        print("尚未下载 GeoIP 数据库。")
    if check_only:
        return 0

    # 统一走 Guard.update_geoip：支持 MAXMIND_LICENSE_KEY 官方直链，失败再回退镜像
    from traffic_guard.core import Guard

    print("开始下载…（如已配置 MAXMIND_LICENSE_KEY 将优先使用官方直链）")
    guard = Guard()
    res = guard.update_geoip()
    if res.get("ok"):
        print(f'完成：{res.get("path")}（{res.get("size", 0) / 1e6:.2f} MB）')
        print("自检：8.8.8.8 ->", guard.geo.lookup("8.8.8.8")["country_cn"])
        guard.stop()
        return 0
    print(f'下载失败：{res.get("error")}')
    guard.stop()
    print("可手动下载 GeoLite2-Country.mmdb 放到数据目录，或配置 MAXMIND_LICENSE_KEY。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
