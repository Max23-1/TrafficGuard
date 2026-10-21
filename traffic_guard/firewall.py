"""防火墙截流：通过 Windows 筛选平台（netsh advfirewall）落地规则。

设计要点：
  * 规则名统一前缀 TG- ，便于列出与清理；
  * 默认按「进程 + 远端 IP」双向限定，避免误伤同机其它程序；
  * 全局断流（熔断）只封锁公网网段，保留局域网 / 回环，避免自锁；
  * 无管理员权限时不伪造成功，明确返回失败原因。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

RULE_PREFIX = "TG-"
KILL_RULE_V4 = RULE_PREFIX + "KILLSWITCH-V4"
KILL_RULE_V6 = RULE_PREFIX + "KILLSWITCH-V6"

# 公网 IPv4 网段（排除 10/8、100.64/10、127/8、169.254/16、172.16/12、192.168/16 与组播/保留段）
PUBLIC_V4_RANGES = ",".join([
    "1.0.0.0-9.255.255.255",
    "11.0.0.0-100.63.255.255",
    "100.128.0.0-126.255.255.255",
    "128.0.0.0-169.253.255.255",
    "169.255.0.0-172.15.255.255",
    "172.32.0.0-192.167.255.255",
    "192.169.0.0-223.255.255.255",
])
PUBLIC_V6_RANGES = "2000::/3"


def _decode(raw: bytes) -> str:
    for enc in ("mbcs", "utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


class FirewallError(RuntimeError):
    pass


class Firewall:
    def __init__(self, simulate: bool = False):
        self.simulate = simulate or os.environ.get("TG_SIMULATE") == "1"
        self._lock = threading.RLock()
        self.last_error: Optional[str] = None
        self.log: List[Dict[str, Any]] = []

    # ------------------------------------------------------------ 基础执行
    def _run(self, args: List[str]) -> Dict[str, Any]:
        cmd = ["netsh", "advfirewall", "firewall"] + args
        if self.simulate:
            self._append_log(cmd, 0, "(simulate)")
            return {"ok": True, "code": 0, "out": "(simulate) " + " ".join(args)}
        try:
            proc = subprocess.run(
                cmd, capture_output=True, timeout=25,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.last_error = f"执行失败: {exc}"
            return {"ok": False, "code": -1, "out": str(exc)}
        out = _decode(proc.stdout or b"") + _decode(proc.stderr or b"")
        ok = proc.returncode == 0 and not re.search(r"错误|Error|失败|拒绝访问", out)
        if not ok:
            self.last_error = out.strip() or f"netsh 返回 {proc.returncode}"
        self._append_log(cmd, proc.returncode, out.strip())
        return {"ok": ok, "code": proc.returncode, "out": out.strip()}

    def _append_log(self, cmd: List[str], code: int, out: str) -> None:
        self.log.append({"ts": time.time(), "cmd": " ".join(cmd), "code": code, "out": out[:400]})
        if len(self.log) > 300:
            del self.log[:150]

    @staticmethod
    def rule_name(kind: str, ip: str, process_path: str = "") -> str:
        seed = f"{kind}|{ip}|{process_path}".encode()
        return f"{RULE_PREFIX}{kind.upper()}-{hashlib.sha1(seed).hexdigest()[:12]}"

    # ------------------------------------------------------------ 单条拦截
    def block(self, ip: str, process_path: str = "", note: str = "") -> Dict[str, Any]:
        """拦截到指定远端 IP 的出站流量。process_path 为空则拦截全部进程。"""
        with self._lock:
            kind = "blk" if process_path else "blkip"
            name = self.rule_name(kind, ip, process_path)
            args = [
                "add", "rule", f'name={name}', "dir=out", "action=block",
                f"remoteip={ip}", "profile=any", "enable=yes",
                f'description=TrafficGuard {note or ""}'.rstrip(),
            ]
            if process_path:
                args.append(f'program={process_path}')
            res = self._run(args)
            res.update(name=name, ip=ip, process=process_path)
            if not res["ok"]:
                res["hint"] = "需要以管理员身份运行本程序才能写入防火墙规则"
            return res

    def unblock(self, name: str) -> Dict[str, Any]:
        with self._lock:
            return self._run(["delete", "rule", f"name={name}"])

    # ------------------------------------------------------------ 熔断开关
    def kill_switch(self, enabled: bool) -> Dict[str, Any]:
        with self._lock:
            if enabled:
                r1 = self._run([
                    "add", "rule", f"name={KILL_RULE_V4}", "dir=out", "action=block",
                    f"remoteip={PUBLIC_V4_RANGES}", "profile=any", "enable=yes",
                    "description=TrafficGuard 全局断流(IPv4)",
                ])
                r2 = self._run([
                    "add", "rule", f"name={KILL_RULE_V6}", "dir=out", "action=block",
                    f"remoteip={PUBLIC_V6_RANGES}", "profile=any", "enable=yes",
                    "description=TrafficGuard 全局断流(IPv6)",
                ])
                return {"ok": r1["ok"] and r2["ok"], "v4": r1, "v6": r2,
                        "hint": None if (r1["ok"] and r2["ok"]) else "需要管理员权限"}
            r1 = self._run(["delete", "rule", f"name={KILL_RULE_V4}"])
            r2 = self._run(["delete", "rule", f"name={KILL_RULE_V6}"])
            return {"ok": True, "v4": r1, "v6": r2}

    def kill_switch_active(self) -> bool:
        if self.simulate:
            return False
        out = self._run(["show", "rule", f"name={KILL_RULE_V4}"]).get("out", "")
        return RULE_PREFIX + "KILLSWITCH-V4" in out

    # ------------------------------------------------------------ 查询与清理
    def list_rules(self) -> List[Dict[str, Any]]:
        """列出本程序创建的规则（解析 netsh 文本输出，兼容中英文）。"""
        if self.simulate:
            return []
        res = self._run(["show", "rule", "name=all", "dir=out"])
        text = res.get("out", "")
        rules: List[Dict[str, Any]] = []
        cur: Optional[Dict[str, Any]] = None
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("规则名称") or s.startswith("Rule Name"):
                name = s.split(":", 1)[-1].strip()
                if name.startswith(RULE_PREFIX):
                    cur = {"name": name, "raw": {}}
                    rules.append(cur)
                else:
                    cur = None
            elif cur is not None and ":" in s:
                k, v = s.split(":", 1)
                cur["raw"][k.strip()] = v.strip()
        for r in rules:
            for k, v in r["raw"].items():
                if k in ("远程 IP", "RemoteIP"):
                    r["remote_ip"] = v
                elif k in ("程序", "Program"):
                    r["program"] = v
                elif k in ("已启用", "Enabled"):
                    r["enabled"] = v
                elif k in ("操作", "Action"):
                    r["action"] = v
        return rules

    def clear_all(self) -> Dict[str, Any]:
        ok = True
        for r in self.list_rules():
            ok = self.unblock(r["name"])["ok"] and ok
        for name in (KILL_RULE_V4, KILL_RULE_V6):
            self._run(["delete", "rule", f"name={name}"])
        return {"ok": ok}

    def verify(self, name: str) -> bool:
        if self.simulate:
            return True
        out = self._run(["show", "rule", f"name={name}"]).get("out", "")
        return name in out

    # ------------------------------------------------------------ 提权
    @staticmethod
    def relaunch_as_admin(argv: List[str], cwd: str) -> bool:
        """以管理员身份重新启动自身，返回是否成功发起。"""
        try:
            exe = argv[0]
            params = subprocess.list2cmdline(argv[1:])
            r = subprocess.run(
                ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
                 f'$p=Start-Process -FilePath "{exe}" -ArgumentList \'{params}\' '
                 f'-WorkingDirectory "{cwd}" -Verb RunAs -PassThru; if($p){{exit 0}}else{{exit 1}}'],
                capture_output=True, timeout=60,
            )
            return r.returncode == 0
        except Exception:  # noqa: BLE001
            return False
