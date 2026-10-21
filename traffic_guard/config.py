"""配置管理：默认配置、读写、迁移、热更新。"""
from __future__ import annotations

import copy
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict

from .paths import data_dir, resource_dir

APP_NAME = "流量哨兵"
APP_ID = "TrafficGuard"

ROOT = resource_dir()
DATA_DIR = data_dir()
CONFIG_PATH = DATA_DIR / "config.json"
STATE_PATH = DATA_DIR / "state.json"
DB_PATH = DATA_DIR / "traffic.db"
LOG_DIR = DATA_DIR / "logs"

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": 1,
    "server": {
        "host": "127.0.0.1",
        "port": 8787,
        "open_browser": True,
    },
    "monitor": {
        "sample_interval": 2.0,
        "retain_minutes": 60,
        "max_flows": 3000,
        "resolve_dns": False,
    },
    "geoip": {
        "db_path": "GeoLite2-Country.mmdb",
        "auto_download": True,
        # 可选：填自己的 MaxMind License Key（或设环境变量 MAXMIND_LICENSE_KEY），
        # 优先走 MaxMind 官方直链，避免依赖第三方镜像。
        "maxmind_license_key": "",
        "download_url": "https://fastly.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-Country.mmdb",
        "mirror_urls": [
            "https://gcore.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-Country.mmdb",
            "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-Country.mmdb",
        ],
    },
    "policy": {
        # monitor 只记录不拦截；standard 高危自动截流；strict 中高危都截流
        "mode": "standard",
        "home_country": "CN",
        # 港澳台单独归为“中国港澳台”，默认不视为海外但仍是跨境链路
        "hmt_as_domestic": False,
        "auto_block_enabled": True,
        "auto_block_threshold": 70,
        "alert_threshold": 40,
        # process: 仅拦截该进程到该 IP；any: 拦截全部进程到该 IP
        "block_scope": "process",
        "alert_timeout_sec": 60,
        "max_alerts_per_minute": 6,
        "silence_minutes": 15,
        "auto_kill_switch_on_quota": False,
    },
    "quota": {
        "enabled": False,
        "daily_gb": 0.0,
        "monthly_gb": 0.0,
        "warn_percent": 90,
        "reset_day": 1,
    },
    "proxy": {
        "process_keywords": [
            "clash", "clash-verge", "clashverge", "mihomo", "v2ray", "v2rayn", "xray",
            "shadowsocks", "ss-local", "ssr", "trojan", "sing-box", "singbox", "nekobox",
            "nekoray", "qv2ray", "hysteria", "naive", "tuic", "wireguard", "openvpn",
            "angelvpn", "tor", "psiphon", "lantern", "shadowsocksr", "gost", "tun2socks",
            "ss-local.exe", "ssr.exe", "outline", "warp", "cloudflare warp", "tailscale",
            "zerotier", "steam++", "watt toolkit", "netch", "proxifier", "surge",
        ],
        "local_listen_ports": [
            1080, 1081, 1086, 1087, 1088, 1089, 7890, 7891, 7892, 7893, 7897, 7898,
            8080, 8118, 8388, 8389, 8889, 9050, 9051, 9090, 9091, 10808, 10809,
            20171, 20172, 2080, 2081, 2086, 2087, 51820, 51821, 1194,
        ],
        "remote_ports": [9050, 9051, 8388, 8389, 1080, 10808, 51820, 1194, 1723, 500, 4500],
        "vpn_adapter_keywords": [
            "tap-windows", "tap adapter", "openvpn", "wireguard", "radmin vpn",
            "clash", "mihomo", "sing-box", "tailscale", "zerotier", "wintun",
            "fortinet", "anyconnect", "softether", "hamachi",
        ],
    },
    "whitelist": {
        "processes": [],
        "ips": [],
        "trust_minutes": 30,
    },
    "ui": {
        "sound": True,
        "popup_enabled": True,
        "popup_always_on_top": True,
        "tray": True,
        "open_window": True,
        "window_width": 1400,
        "window_height": 900,
    },
}

_CONFIG_LOCK = threading.RLock()
_CACHE: Dict[str, Any] | None = None
_CACHE_MTIME = 0.0


def ensure_dirs() -> None:
    for p in (DATA_DIR, LOG_DIR, ROOT / "web"):
        p.mkdir(parents=True, exist_ok=True)

def _deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(force: bool = False) -> Dict[str, Any]:
    """读取配置，缺省项自动补全；文件被外部修改后自动重载。"""
    global _CACHE, _CACHE_MTIME
    with _CONFIG_LOCK:
        ensure_dirs()
        mtime = CONFIG_PATH.stat().st_mtime if CONFIG_PATH.exists() else 0.0
        if _CACHE is not None and not force and mtime == _CACHE_MTIME:
            return _CACHE
        raw: Dict[str, Any] = {}
        if CONFIG_PATH.exists():
            try:
                raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
            except Exception:
                raw = {}
        cfg = _deep_merge(DEFAULT_CONFIG, raw if isinstance(raw, dict) else {})
        if not CONFIG_PATH.exists() or raw != cfg:
            try:
                CONFIG_PATH.write_text(
                    json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8"
                )
                mtime = CONFIG_PATH.stat().st_mtime
            except OSError:
                pass
        _CACHE, _CACHE_MTIME = cfg, mtime
        return cfg


def save_config(patch: Dict[str, Any]) -> Dict[str, Any]:
    global _CACHE, _CACHE_MTIME
    with _CONFIG_LOCK:
        cur = load_config(force=True)
        cfg = _deep_merge(cur, patch)
        CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        _CACHE = cfg
        _CACHE_MTIME = CONFIG_PATH.stat().st_mtime
        return cfg


def cfg_get(path: str, default: Any = None) -> Any:
    """按 a.b.c 取值。"""
    cur: Any = load_config()
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


# ---------------------------------------------------------------- 运行时状态
DEFAULT_STATE: Dict[str, Any] = {
    "installed_at": 0.0,
    "trusted_ips": {},       # ip -> expire_ts
    "blocked_rules": [],     # [{id, ip, process, name, created}]
    "kill_switch": False,
    "totals": {"day": "", "day_in": 0, "day_out": 0, "month": "", "month_in": 0, "month_out": 0},
}


def load_state() -> Dict[str, Any]:
    ensure_dirs()
    st = copy.deepcopy(DEFAULT_STATE)
    if STATE_PATH.exists():
        try:
            raw = json.loads(STATE_PATH.read_text(encoding="utf-8-sig"))
            if isinstance(raw, dict):
                st.update(raw)
        except Exception:
            pass
    if not st.get("installed_at"):
        st["installed_at"] = time.time()
    return st


def save_state(state: Dict[str, Any]) -> None:
    ensure_dirs()
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, STATE_PATH)


def resolve_path(rel: str) -> Path:
    """把配置里的相对路径解析到数据目录（兼容 1.x 的 "data/xxx" 写法）。"""
    p = Path(str(rel))
    if p.is_absolute():
        return p
    parts = list(p.parts)
    if parts and parts[0].lower() == "data":
        parts = parts[1:]
    return DATA_DIR.joinpath(*parts) if parts else DATA_DIR
