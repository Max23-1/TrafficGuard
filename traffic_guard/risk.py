"""风险引擎：判断一条连接「流向哪里、是否跨境/海外、被公安约谈的风险有多高」。"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --- 风险权重（可通过 config.policy.weights 覆盖） -------------------------
DEFAULT_WEIGHTS: Dict[str, int] = {
    "overseas": 35,          # 目的地在中国大陆以外
    "hmt": 20,               # 目的地为港澳台（跨境链路）
    "unknown_geo": 22,       # 无法识别归属地
    "proxy_process": 50,     # 由代理/VPN 客户端发起的连接
    "proxy_port": 40,        # 连到常见代理协议端口
    "tor": 50,               # Tor 相关端口
    "foreign_dns": 25,       # 直接用境外公共 DNS 解析
    "odd_port": 10,          # 海外 + 非常用端口
    "vpn_adapter": 30,       # 本机存在已启用的虚拟专用网卡
    "proxy_listen": 40,      # 本机在监听代理端口
    "system_proxy": 25,      # 系统代理被开启
    "new_peer": 5,           # 首次出现的境外对端
    "large_upload": 10,      # 持续大流量上传到海外
}

LEVELS = [
    (70, "high", "高危"),
    (40, "medium", "中危"),
    (20, "low", "关注"),
    (0, "info", "正常"),
]

# 强特征关键词：直接子串匹配（足够独特，不会误伤）
STRONG_PROXY_KEYWORDS = [
    "clash", "v2ray", "v2rayn", "xray", "shadowsocks", "shadowssocks", "ss-local",
    "ssr", "trojan", "sing-box", "singbox", "mihomo", "hysteria", "tuic", "naive",
    "nekobox", "nekoray", "qv2ray", "gost", "tun2socks", "psiphon", "lantern",
    "wireguard", "openvpn", "outline", "warp", "tailscale", "zerotier", "proxifier",
    "netch", "watt toolkit", "steam++", "sstap", "sockscap", "proxychains",
    "easyconnect", "sangfor", "anyconnect", "softether", "hamachi", "forticlient",
    "expressvpn", "nordvpn", "surfshark", "cyberghost", "astrill",
]
# 弱特征关键词：要求整体匹配（避免 monitor/editor 之类误伤）
WEAK_PROXY_KEYWORDS = {"tor", "ss", "ssr", "vpn", "proxy", "socks", "tun", "tap"}

FOREIGN_DNS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
               "208.67.222.222", "208.67.220.220", "64.6.64.6", "77.88.8.8",
               "94.140.14.14", "45.90.28.0", "76.76.2.0"}

COMMON_PORTS = {
    80, 443, 8080, 8443, 53, 123, 853, 993, 995, 587, 465, 110, 143, 22, 21,
    5222, 5223, 3478, 3479, 19302, 19303, 19304, 19305, 27015, 27016, 27017,
    27036, 27037, 3074, 3478, 500, 4500, 1194, 1723, 5004, 5005, 5060, 5061,
    6881, 6882, 6889, 25565, 7777, 8086, 9001, 9030, 9050, 9051,
    1935, 554, 8555, 10000, 1194, 1883, 8883, 3478,
}

TOR_PORTS = {9001, 9030, 9050, 9051, 9150, 9040, 9041, 443}

DISCLAIMER = (
    "本功能仅做技术层面的跨境流量识别与风险提示，不构成法律意见。"
    "依据《中华人民共和国网络安全法》《计算机信息网络国际联网管理暂行规定》等，"
    "未经批准私自搭建、使用跨境联网通道存在合规风险；请以主管部门解释为准。"
)


def level_of(score: int) -> Tuple[str, str]:
    for thr, key, cn in LEVELS:
        if score >= thr:
            return key, cn
    return "info", "正常"


def _stem(name: str) -> str:
    n = (name or "").strip().lower()
    for suffix in (".exe", ".com", ".scr", ".bat", ".cmd"):
        if n.endswith(suffix):
            n = n[: -len(suffix)]
    return n


def looks_like_proxy(process_name: str, keywords: Iterable[str] | None = None) -> Optional[str]:
    """判断进程名是否是代理/VPN 客户端，返回命中的关键词。"""
    stem = _stem(process_name)
    if not stem:
        return None
    kws = list(keywords) if keywords is not None else STRONG_PROXY_KEYWORDS
    for kw in kws:
        k = kw.strip().lower()
        if not k:
            continue
        if k in STRONG_PROXY_KEYWORDS:
            if k in stem:
                return k
        else:
            if stem == k or stem.startswith(k + "-") or stem.startswith(k + "_") \
                    or stem.endswith("-" + k) or stem.endswith("_" + k) or f"-{k}-" in stem:
                return k
    for k in WEAK_PROXY_KEYWORDS:
        if stem == k or stem.startswith(k + "-") or stem.startswith(k + "_"):
            return k
    return None


@dataclass
class FlowRisk:
    score: int = 0
    level: str = "info"
    level_cn: str = "正常"
    reasons: List[str] = field(default_factory=list)
    action: str = "log"          # log | alert | block
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score, "level": self.level, "level_cn": self.level_cn,
            "reasons": self.reasons, "action": self.action, "tags": self.tags,
        }


class RiskEngine:
    def __init__(self, policy: Dict[str, Any], proxy_cfg: Dict[str, Any], whitelist: Dict[str, Any]):
        self.policy = policy or {}
        self.proxy_cfg = proxy_cfg or {}
        self.whitelist = whitelist or {}
        self.weights = dict(DEFAULT_WEIGHTS)
        self.weights.update(self.policy.get("weights") or {})
        self.home = (self.policy.get("home_country") or "CN").upper()
        self.hmt_as_domestic = bool(self.policy.get("hmt_as_domestic"))
        self.mode = (self.policy.get("mode") or "standard").lower()
        self.block_threshold = int(self.policy.get("auto_block_threshold", 70))
        self.alert_threshold = int(self.policy.get("alert_threshold", 40))
        self.block_enabled = bool(self.policy.get("auto_block_enabled", True))
        self.custom_keywords = [str(k) for k in (self.proxy_cfg.get("process_keywords") or [])]
        self.local_ports = set(int(p) for p in (self.proxy_cfg.get("local_listen_ports") or []))
        self.remote_ports = set(int(p) for p in (self.proxy_cfg.get("remote_ports") or []))
        self.whitelist_procs = {str(p).lower() for p in (self.whitelist.get("processes") or [])}
        self.whitelist_ips = {str(p) for p in (self.whitelist.get("ips") or [])}

    # ------------------------------------------------------------------ 流
    def is_whitelisted_process(self, process_name: str, exe: str = "") -> bool:
        n = (process_name or "").lower()
        e = (exe or "").lower()
        return n in self.whitelist_procs or (e and e in self.whitelist_procs)

    def evaluate_flow(self, flow: Dict[str, Any], geo: Dict[str, Any],
                      env: Optional[Dict[str, Any]] = None) -> FlowRisk:
        """flow: {remote_ip, remote_port, proto, process, exe, state}；geo: GeoResolver.lookup 结果。"""
        env = env or {}
        risk = FlowRisk()
        score = 0
        reasons: List[str] = []
        tags: List[str] = []

        remote_ip = flow.get("remote_ip") or ""
        port = int(flow.get("remote_port") or 0)
        proc_name = flow.get("process") or ""
        scope = geo.get("scope") or "UNKNOWN"

        if remote_ip in self.whitelist_ips:
            risk.score = 0
            risk.reasons = ["该 IP 在信任列表中，已跳过风险判定"]
            risk.level, risk.level_cn = level_of(0)
            return risk
        if self.is_whitelisted_process(proc_name, flow.get("exe", "")):
            risk.score = 0
            risk.reasons = ["该进程在信任列表中，已跳过风险判定"]
            risk.level, risk.level_cn = level_of(0)
            return risk

        cross_border = scope in ("OVERSEAS", "HMT", "UNKNOWN")
        if scope == "OVERSEAS":
            score += self.weights["overseas"]
            reasons.append(f"目的地为境外（{geo.get('country_cn') or geo.get('iso') or '未知'}）")
            tags.append("overseas")
        elif scope == "HMT":
            score += self.weights["hmt"]
            reasons.append(f"目的地为中国港澳台（{geo.get('country_cn')}），属跨境链路")
            tags.append("hmt")
        elif scope == "UNKNOWN":
            score += self.weights["unknown_geo"]
            reasons.append("目的地归属地无法识别")
            tags.append("unknown")

        proxy_kw = looks_like_proxy(proc_name, self.custom_keywords)
        if proxy_kw:
            score += self.weights["proxy_process"]
            reasons.append(f"该连接由代理/翻墙类客户端发起（命中特征：{proxy_kw}）")
            tags.append("proxy-process")

        if port in TOR_PORTS and port not in (443,):
            score += self.weights["tor"]
            reasons.append(f"连接 Tor 常用端口 {port}")
            tags.append("tor")
        elif port in self.remote_ports and port not in (443, 80):
            score += self.weights["proxy_port"]
            reasons.append(f"连接代理/VPN 常用端口 {port}")
            tags.append("proxy-port")

        if remote_ip in FOREIGN_DNS and port in (53, 853, 443):
            score += self.weights["foreign_dns"]
            reasons.append(f"直接使用境外公共 DNS（{remote_ip}），可能绕过境内解析")
            tags.append("foreign-dns")

        if cross_border and port not in COMMON_PORTS and port not in (443, 80):
            score += self.weights["odd_port"]
            reasons.append(f"跨境流量使用非常用端口 {port}")

        if scope == "OVERSEAS" and (env.get("vpn_adapters") or []) and proxy_kw:
            score += self.weights["vpn_adapter"] // 3
            reasons.append("本机存在已启用的虚拟专用网卡，该流量可能经隧道出境")
            tags.append("vpn-path")

        if proxy_kw and not cross_border:
            score -= 10  # 本地代理链路本身不算跨境

        score = max(0, min(100, score))
        risk.score = score
        risk.reasons = reasons
        risk.tags = tags
        risk.level, risk.level_cn = level_of(score)

        blocked_by_mode = self.block_enabled and (
            (self.mode == "standard" and score >= self.block_threshold)
            or (self.mode == "strict" and score >= self.alert_threshold)
        )
        if self.mode == "monitor" or not self.block_enabled:
            risk.action = "alert" if score >= self.alert_threshold else "log"
        elif blocked_by_mode:
            risk.action = "block"
        elif score >= self.alert_threshold:
            risk.action = "alert"
        else:
            risk.action = "log"
        return risk

    # ------------------------------------------------------------------ 环境
    def evaluate_environment(self, listeners: List[Dict[str, Any]],
                             adapters: List[Dict[str, Any]],
                             processes: List[Dict[str, Any]],
                             system_proxy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """整机「约谈风险」评估：是否存在代理工具、跨境隧道、系统代理等。"""
        findings: List[Dict[str, Any]] = []
        score = 0

        proxy_listeners = []
        for l in listeners:
            port = int(l.get("port") or 0)
            pname = l.get("process") or ""
            kw = looks_like_proxy(pname, self.custom_keywords)
            if kw or (port in self.local_ports and l.get("local_ip") in ("127.0.0.1", "0.0.0.0", "::1", "::")):
                proxy_listeners.append({**l, "matched": kw or f"端口 {port}"})
        if proxy_listeners:
            score += self.weights["proxy_listen"]
            detail = "、".join(
                f"{x.get('process') or 'PID ' + str(x.get('pid'))} 监听 {x.get('local_ip')}:{x.get('port')}"
                for x in proxy_listeners[:4]
            )
            findings.append({
                "kind": "proxy_listen", "level": "high", "score": self.weights["proxy_listen"],
                "title": "本机正在运行代理/翻墙类服务",
                "detail": detail,
                "advice": "如该服务未经批准提供跨境联网，存在被主管部门约谈、行政处罚的风险。",
            })

        proxy_procs = []
        for p in processes:
            kw = looks_like_proxy(p.get("name") or "", self.custom_keywords)
            if kw:
                proxy_procs.append((p, kw))
        if proxy_procs:
            add = min(self.weights["proxy_process"], 40)
            score += add
            names = "、".join(f"{p.get('name')}({kw})" for p, kw in proxy_procs[:5])
            findings.append({
                "kind": "proxy_process", "level": "high", "score": add,
                "title": "检测到代理/翻墙类客户端进程",
                "detail": names,
                "advice": "该类工具是执法关注重点，建议确认其合规性并保留使用记录。",
            })

        vpn_adapters = [a for a in adapters
                        if any(k in ((a.get("desc") or "") + " " + (a.get("name") or "")).lower()
                               for k in (self.proxy_cfg.get("vpn_adapter_keywords") or []))]
        if vpn_adapters:
            score += self.weights["vpn_adapter"]
            findings.append({
                "kind": "vpn_adapter", "level": "medium", "score": self.weights["vpn_adapter"],
                "title": "存在已启用的虚拟专用网卡",
                "detail": "、".join(f"{a.get('name')}（{a.get('desc')}）" for a in vpn_adapters[:4]),
                "advice": "虚拟网卡通常意味着流量隧道；请确认其用途与合规性。",
            })

        if system_proxy and system_proxy.get("enabled"):
            score += self.weights["system_proxy"]
            findings.append({
                "kind": "system_proxy", "level": "medium", "score": self.weights["system_proxy"],
                "title": "系统代理已开启",
                "detail": f"ProxyServer = {system_proxy.get('server') or '(未填写)'}",
                "advice": "系统级代理常用于全流量转发，建议核实其指向的服务器。",
            })

        score = max(0, min(100, score))
        level_key, level_cn = level_of(score)
        return {
            "score": score, "level": level_key, "level_cn": level_cn,
            "findings": findings,
            "vpn_adapters": [a for a in vpn_adapters],
            "proxy_listeners": proxy_listeners,
            "disclaimer": DISCLAIMER,
            "ts": time.time(),
        }
