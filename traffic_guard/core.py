"""核心：采样、流表、风险判定、截流、决策。"""
from __future__ import annotations

import os
import queue
import threading
import time
import uuid
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional

from . import winapi as W
from .config import (DB_PATH, LOG_DIR, load_config, load_state, resolve_path,
                     save_config, save_state)
from .firewall import Firewall
from .geoip import GeoResolver
from .logging_util import setup_logging
from .paths import ensure_geoip
from .risk import DISCLAIMER, RiskEngine, level_of
from .store import Store

VERSION = "2.1.0"

# 这些进程即使命中风险也不自动拦截，否则会直接导致系统断网
NEVER_BLOCK = {
    "svchost.exe", "lsass.exe", "wininit.exe", "services.exe", "csrss.exe",
    "smss.exe", "winlogon.exe", "system", "system idle", "ntoskrnl.exe",
    "dwm.exe", "spoolsv.exe", "audiodg.exe", "msmpeng.exe",
}

FLOW_IDLE_TIMEOUT = 45.0


def _today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def _month() -> str:
    return datetime.now().strftime("%Y-%m")


def _fmt_gb(n: float) -> float:
    return round(n / (1024 ** 3), 3)


class Guard:
    def __init__(self, popup_queue: Optional[queue.Queue] = None):
        self.cfg = load_config()
        self.state = load_state()
        self.log = setup_logging(LOG_DIR)
        self.lock = threading.RLock()
        self.db = Store(DB_PATH)
        self.fw = Firewall()
        self.admin = W.is_admin()
        self.fw_ready = W.firewall_available()
        self.popup_q: queue.Queue = popup_queue or queue.Queue()
        self.alert_q: queue.Queue = queue.Queue()
        self.flows: Dict[str, Dict[str, Any]] = {}
        self.proc_prev: Dict[int, Dict[str, Any]] = {}
        self.events: deque = deque(maxlen=400)
        try:  # 恢复最近事件，重启后风险面板与时间线不至于为空
            for ev in reversed(self.db.list_events(80)):
                self.events.appendleft(ev)
        except Exception:  # noqa: BLE001
            pass
        self.pending: Dict[str, Dict[str, Any]] = {}
        self.blocked: Dict[str, Dict[str, Any]] = dict(
            (r["name"], r) for r in (self.state.get("blocked_rules") or [])
        )
        self.trusted_ips: Dict[str, float] = dict(self.state.get("trusted_ips") or {})
        self.trusted_procs: Dict[str, float] = {}
        self.kill_switch = bool(self.state.get("kill_switch"))
        self.rates = {"rx": 0.0, "tx": 0.0}
        self.session_total = {"rx": 0, "tx": 0}
        self.prev_iface: Optional[tuple] = None
        self.env: Dict[str, Any] = {"score": 0, "level": "low", "level_cn": "低",
                                    "findings": [], "disclaimer": DISCLAIMER}
        self.started_at = time.time()
        self.last_tick = 0.0
        self.tick_count = 0
        self.alert_times: deque = deque(maxlen=300)
        self._event_dedupe: Dict[tuple, float] = {}
        self.suppressed = 0
        self.block_failures = 0
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self.geo = GeoResolver(
            ensure_geoip(resolve_path(self.cfg["geoip"]["db_path"])),
            home_country=self.cfg["policy"]["home_country"],
            hmt_as_domestic=bool(self.cfg["policy"].get("hmt_as_domestic")),
        )
        self.risk_engine = self._build_risk_engine()
        self._last_env = 0.0
        self._last_persist = 0.0
        self._persist_dirty = False
        self.shutdown_event = threading.Event()
        self.on_shutdown = None  # type: ignore[assignment]
        self.iface_adapters: List[Dict[str, Any]] = []
        self.quota_hit = {"day": False, "month": False}
        self._normalize_totals()

    # ------------------------------------------------------------------ 初始化
    def _build_risk_engine(self) -> RiskEngine:
        return RiskEngine(self.cfg["policy"], self.cfg["proxy"], self.cfg["whitelist"])

    def _normalize_totals(self) -> None:
        t = self.state.setdefault("totals", {})
        if t.get("day") != _today():
            t.update(day=_today(), day_in=0, day_out=0)
        if t.get("month") != _month():
            t.update(month=_month(), month_in=0, month_out=0)
        t.setdefault("day", _today())
        t.setdefault("month", _month())
        t.setdefault("day_in", 0)
        t.setdefault("day_out", 0)
        t.setdefault("month_in", 0)
        t.setdefault("month_out", 0)

    # ------------------------------------------------------------------ 线程
    def start(self) -> None:
        for target, name in ((self._loop, "sampler"), (self._alert_worker, "alert-worker")):
            th = threading.Thread(target=target, name=name, daemon=True)
            th.start()
            self._threads.append(th)
        self.log.info("流量哨兵已启动（管理员=%s，模式=%s）", self.admin,
                      self.cfg["policy"]["mode"])

    def stop(self) -> None:
        self._stop.set()
        self._persist(force=True)
        try:
            self.db.close()
        except Exception:  # noqa: BLE001
            pass

    def _loop(self) -> None:
        while not self._stop.is_set():
            interval = max(1.0, float(self.cfg["monitor"]["sample_interval"]))
            t0 = time.time()
            try:
                self.tick()
            except Exception as exc:  # noqa: BLE001
                self.log.exception("采样异常: %s", exc)
            wait = interval - (time.time() - t0)
            self._stop.wait(max(0.2, wait))

    # ------------------------------------------------------------------ 采样
    def tick(self) -> None:
        cfg = load_config()
        if cfg != self.cfg:
            self.cfg = cfg
            self.risk_engine = self._build_risk_engine()
        now = time.time()
        dt = max(0.2, now - self.last_tick) if self.last_tick else float(cfg["monitor"]["sample_interval"])
        self.last_tick = now

        # 1. 网卡总量
        iface_delta_in = iface_delta_out = 0
        try:
            stats = W.interface_stats()
            self.iface_adapters = stats["adapters"]
            cur = (stats["rx"], stats["tx"])
            if self.prev_iface:
                iface_delta_in = max(0, cur[0] - self.prev_iface[0])
                iface_delta_out = max(0, cur[1] - self.prev_iface[1])
            self.prev_iface = cur
            self._accumulate_totals(iface_delta_in, iface_delta_out)
            alpha = 0.35
            self.rates["rx"] = alpha * (iface_delta_in / dt) + (1 - alpha) * self.rates["rx"]
            self.rates["tx"] = alpha * (iface_delta_out / dt) + (1 - alpha) * self.rates["tx"]
        except Exception as exc:  # noqa: BLE001
            self.log.warning("读取网卡计数失败: %s", exc)

        # 2. 连接表
        try:
            conns = W.tcp_connections(include_listen=False)
        except Exception as exc:  # noqa: BLE001
            self.log.warning("读取 TCP 表失败: %s", exc)
            conns = []

        seen_keys = set()
        active_pids = set()
        with self.lock:
            for c in conns:
                if c["state"] not in ("ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"):
                    continue
                rip = c["remote_ip"]
                if not rip or rip in ("0.0.0.0", "::"):
                    continue
                key = f'{c["proto"]}|{c["local_ip"]}:{c["local_port"]}|{rip}:{c["remote_port"]}|{c["pid"]}'
                seen_keys.add(key)
                flow = self.flows.get(key)
                if flow is None:
                    flow = self._new_flow(key, c, now)
                    self.flows[key] = flow
                flow["last_seen"] = now
                flow["state"] = c["state"]
                if flow["pid"] != c["pid"]:
                    flow["pid"] = c["pid"]
                    flow["process"] = ""
                    flow["risk_evaluated"] = False
                if flow["process"] and flow["pid"]:
                    active_pids.add(flow["pid"])
                if not flow["risk_evaluated"]:
                    self._evaluate_flow(flow)
            # 清理过期流
            dead = [k for k, f in self.flows.items() if now - f["last_seen"] > FLOW_IDLE_TIMEOUT]
            for k in dead:
                self.flows.pop(k, None)

        # 3. 字节归属（按进程 IO 增量估算，再按连接数均分）
        self._attribute_bytes(dt, iface_delta_in, iface_delta_out, active_pids)

        # 4. 环境风险
        if now - self._last_env > 60:
            self._last_env = now
            try:
                self._evaluate_environment()
            except Exception as exc:  # noqa: BLE001
                self.log.warning("环境风险评估失败: %s", exc)

        # 5. 配额
        self._check_quota()

        self.tick_count += 1
        self._persist()

    def _new_flow(self, key: str, c: Dict[str, Any], now: float) -> Dict[str, Any]:
        proc = W.process_info(c["pid"])
        geo = self.geo.lookup(c["remote_ip"])
        return {
            "id": key, "proto": c["proto"], "local_ip": c["local_ip"],
            "local_port": c["local_port"], "remote_ip": c["remote_ip"],
            "remote_port": c["remote_port"], "pid": c["pid"],
            "process": proc.get("name") or "", "exe": proc.get("exe") or "",
            "app": proc.get("app") or "", "app_company": proc.get("app_company") or "",
            "state": c["state"], "country": geo.get("country_cn") or "",
            "country_cn": geo.get("country_cn") or "", "iso": geo.get("iso") or "",
            "scope": geo.get("scope") or "UNKNOWN",
            "score": 0, "level": "info", "level_cn": "正常", "reasons": [], "tags": [],
            "action": "log", "rx": 0.0, "tx": 0.0, "rx_rate": 0.0, "tx_rate": 0.0,
            "first_seen": now, "last_seen": now, "risk_evaluated": False,
            "status": "normal",
        }

    def _evaluate_flow(self, flow: Dict[str, Any]) -> None:
        geo = self.geo.lookup(flow["remote_ip"])
        flow.update(country_cn=geo.get("country_cn"), iso=geo.get("iso"), scope=geo.get("scope"))
        if not flow.get("process") and flow.get("pid"):
            proc = W.process_info(flow["pid"])
            flow["process"] = proc.get("name") or ""
            flow["exe"] = proc.get("exe") or ""
        if not flow.get("app") and flow.get("pid"):
            proc = W.process_info(flow["pid"])
            flow["app"] = proc.get("app") or ""
            flow["app_company"] = proc.get("app_company") or ""
        risk = self.risk_engine.evaluate_flow(flow, geo, {"vpn_adapters": self.env.get("vpn_adapters") or []})
        flow.update(
            score=risk.score, level=risk.level, level_cn=risk.level_cn,
            reasons=risk.reasons, tags=risk.tags, action=risk.action,
        )
        flow["risk_evaluated"] = True
        if risk.score >= int(self.cfg["policy"]["alert_threshold"]):
            self._on_risky_flow(flow, risk)

    # ------------------------------------------------------------------ 风险处置
    def _on_risky_flow(self, flow: Dict[str, Any], risk) -> None:
        now = time.time()
        trust_until = max(self.trusted_ips.get(flow["remote_ip"], 0),
                          self.trusted_procs.get(flow["process"].lower(), 0))
        if trust_until > now:
            flow["status"] = "trusted"
            return
        for p in self.pending.values():
            if p["flow"]["remote_ip"] == flow["remote_ip"] and p["flow"]["process"] == flow["process"]:
                flow["status"] = "pending"
                return
        if self._is_already_blocked(flow["remote_ip"], flow["process"]):
            flow["status"] = "blocked"
            return

        # 同一「进程 + 远端」15 分钟内只记一条事件，避免连接复用导致刷屏
        dkey = (flow.get("process", ""), flow["remote_ip"])
        if now - float(self._event_dedupe.get(dkey, 0)) < 900:
            return
        self._event_dedupe[dkey] = now
        if len(self._event_dedupe) > 5000:
            self._event_dedupe.clear()

        event = self._make_event(
            kind="flow", level=risk.level, score=risk.score,
            title=f'{flow["process"] or "未知进程"} → {flow["remote_ip"]}:{flow["remote_port"]}（{flow["country_cn"]}）',
            detail="；".join(risk.reasons) or "命中风险规则",
            flow=flow, action=risk.action, state="open",
        )
        if risk.action != "block":
            return

        # 频率控制：超限时仍然记录，但不弹窗，避免风暴
        self.alert_times.append(now)
        recent = [t for t in self.alert_times if now - t <= 60]
        if len(recent) > int(self.cfg["policy"]["max_alerts_per_minute"]):
            self.suppressed += 1
            self.db.update_event_state(event["id"], "suppressed")
            return

        alert = {
            "id": event["id"], "event_id": event["id"], "created": now,
            "deadline": now + float(self.cfg["policy"]["alert_timeout_sec"]),
            "flow": dict(flow), "risk": risk.to_dict(), "rule": None,
            "status": "blocking", "block_result": None,
            "handled": False,
        }
        self.pending[alert["id"]] = alert
        flow["status"] = "pending"
        self.alert_q.put(alert)
        self._persist_dirty = True

    def _is_already_blocked(self, ip: str, process: str) -> bool:
        for r in self.blocked.values():
            if r.get("ip") == ip and r.get("process_name") in ("", process):
                return True
        return False

    def _make_event(self, **kw) -> Dict[str, Any]:
        flow = kw.pop("flow", None) or {}
        ev = {
            "id": str(uuid.uuid4()), "ts": time.time(), "kind": kw.get("kind", "flow"),
            "level": kw.get("level", "info"), "score": int(kw.get("score", 0)),
            "title": kw.get("title", ""), "detail": kw.get("detail", ""),
            "process": flow.get("process", kw.get("process", "")),
            "pid": int(flow.get("pid", kw.get("pid", 0)) or 0),
            "app": flow.get("app", kw.get("app", "")) or "",
            "ip": flow.get("remote_ip", kw.get("ip", "")),
            "port": int(flow.get("remote_port", kw.get("port", 0)) or 0),
            "country_iso": flow.get("iso", ""), "country_cn": flow.get("country_cn", ""),
            "action": kw.get("action", "log"), "state": kw.get("state", "open"),
            "extra": kw.get("extra") or {},
        }
        with self.lock:
            self.events.appendleft(ev)
        try:
            self.db.add_event(ev)
        except Exception as exc:  # noqa: BLE001
            self.log.warning("写入事件失败: %s", exc)
        return ev

    # ------------------------------------------------------------------ 字节归属
    def _attribute_bytes(self, dt: float, d_in: int, d_out: int, active_pids: set) -> None:
        weights: Dict[int, float] = {}
        for pid in list(active_pids):
            io = W.process_io(pid)
            prev = self.proc_prev.get(pid)
            if io and prev:
                dr = max(0, io[0] - prev["io"][0])
                dw = max(0, io[1] - prev["io"][1])
                weights[pid] = dr + dw
            if io:
                self.proc_prev[pid] = {"io": io, "ts": time.time()}
        if len(self.proc_prev) > 4096:
            self.proc_prev.clear()

        total_w = sum(weights.values())
        if total_w > 0 and (d_in + d_out) > 0:
            scale = (d_in + d_out) / total_w
            scale = max(0.02, min(4.0, scale))
        else:
            scale = 0.0

        by_pid: Dict[int, List[Dict[str, Any]]] = {}
        with self.lock:
            for flow in self.flows.values():
                by_pid.setdefault(flow["pid"], []).append(flow)
            for pid, flows in by_pid.items():
                if scale <= 0 or pid not in weights:
                    for f in flows:
                        f["rx_rate"] = 0.0
                        f["tx_rate"] = 0.0
                    continue
                share = weights[pid] * scale
                n = len(flows) or 1
                for f in flows:
                    add = share / n
                    inb = add * (d_in / (d_in + d_out) if (d_in + d_out) else 0.5)
                    outb = add - inb
                    f["rx"] += inb
                    f["tx"] += outb
                    f["rx_rate"] = inb / dt
                    f["tx_rate"] = outb / dt
            self.session_total["rx"] += d_in
            self.session_total["tx"] += d_out

    # ------------------------------------------------------------------ 总量
    def _accumulate_totals(self, d_in: int, d_out: int) -> None:
        if d_in <= 0 and d_out <= 0:
            return
        t = self.state.setdefault("totals", {})
        today, month = _today(), _month()
        if t.get("day") != today:
            t.update(day=today, day_in=0, day_out=0)
            self.quota_hit["day"] = False
        if t.get("month") != month:
            t.update(month=month, month_in=0, month_out=0)
            self.quota_hit["month"] = False
        t["day_in"] = int(t.get("day_in", 0)) + d_in
        t["day_out"] = int(t.get("day_out", 0)) + d_out
        t["month_in"] = int(t.get("month_in", 0)) + d_in
        t["month_out"] = int(t.get("month_out", 0)) + d_out
        self._persist_dirty = True
        try:
            self.db.add_traffic(today, d_in, d_out)
        except Exception:  # noqa: BLE001
            pass

    def _check_quota(self) -> None:
        q = self.cfg["quota"]
        if not q.get("enabled"):
            return
        t = self.state.get("totals", {})
        for scope, limit_gb, used in (
            ("day", float(q.get("daily_gb") or 0), t.get("day_in", 0) + t.get("day_out", 0)),
            ("month", float(q.get("monthly_gb") or 0), t.get("month_in", 0) + t.get("month_out", 0)),
        ):
            if limit_gb <= 0 or self.quota_hit.get(scope):
                continue
            limit = limit_gb * (1024 ** 3)
            warn_at = limit * float(q.get("warn_percent", 90)) / 100.0
            if used >= limit:
                self.quota_hit[scope] = True
                self._on_quota_exceeded(scope, used, limit)
            elif used >= warn_at:
                key = f"quota_warn_{scope}_{t.get(scope)}"
                if not self.state.get(key):
                    self.state[key] = True
                    self._make_event(
                        kind="quota", level="medium", score=45,
                        title=f"{'今日' if scope == 'day' else '本月'}流量已达 {used / limit * 100:.0f}% 配额",
                        detail=f"已用 {_fmt_gb(used)} GB / 上限 {limit_gb} GB",
                        action="alert", state="open",
                    )

    def _on_quota_exceeded(self, scope: str, used: float, limit: float) -> None:
        name = "今日" if scope == "day" else "本月"
        ev = self._make_event(
            kind="quota", level="high", score=80,
            title=f"{name}流量超限，已触发断流",
            detail=f"已用 {_fmt_gb(used)} GB，上限 {limit / 1024 ** 3:.2f} GB",
            action="block", state="open",
        )
        if bool(self.cfg["policy"].get("auto_kill_switch_on_quota")):
            self.control("kill_switch_on", reason=f"{name}流量超限")
        self.popup_q.put({
            "kind": "quota", "id": ev["id"], "title": f"{name}流量已超限",
            "lines": [
                f"已使用：{_fmt_gb(used)} GB",
                f"配额上限：{limit / 1024 ** 3:.2f} GB",
                "已按设置自动断流。" if self.cfg["policy"].get("auto_kill_switch_on_quota")
                else "可前往控制台开启全局断流。",
            ],
            "primary": "知道了", "secondary": None,
        })

    # ------------------------------------------------------------------ 环境
    def _evaluate_environment(self) -> None:
        try:
            tcp_all = W.tcp_connections(include_listen=True)
        except Exception:  # noqa: BLE001
            tcp_all = []
        listeners = []
        for c in tcp_all:
            if c["state"] != "LISTEN":
                continue
            proc = W.process_info(c["pid"])
            listeners.append({
                "local_ip": c["local_ip"], "port": c["local_port"],
                "pid": c["pid"], "process": proc.get("name") or "",
            })
        processes = []
        for pid in W.list_pids()[:600]:
            info = W.process_info(pid)
            if info.get("name"):
                processes.append(info)
        sysproxy = W.system_proxy()
        adapters = self.iface_adapters
        env = self.risk_engine.evaluate_environment(listeners, adapters, processes, sysproxy)
        with self.lock:
            self.env = env
        # 新出现的高危环境发现 -> 记一条事件（同一 kind 24 小时内只记一次）
        for f in env.get("findings", []):
            if f.get("level") != "high":
                continue
            key = f"env_seen_{f['kind']}"
            if time.time() - float(self.state.get(key) or 0) > 86400:
                self.state[key] = time.time()
                self._make_event(
                    kind=f["kind"], level="high", score=f.get("score", 0),
                    title=f["title"], detail=f["detail"], action="alert", state="open",
                    extra={"advice": f.get("advice", "")},
                )
                self._persist_dirty = True

    # ------------------------------------------------------------------ 决策
    def decide(self, alert_id: str, decision: str) -> Dict[str, Any]:
        """decision: continue(继续连接/解除拦截) | block(保持断开)。"""
        with self.lock:
            alert = self.pending.get(alert_id)
            if not alert:
                return {"ok": False, "error": "该提醒不存在或已处理"}
            if alert.get("handled"):
                return {"ok": False, "error": "该提醒已处理"}
            alert["handled"] = True
            flow = alert["flow"]
            rule = alert.get("rule")

        if decision == "continue":
            if rule:
                self.fw.unblock(rule)
                with self.lock:
                    self.blocked.pop(rule, None)
            minutes = float(self.cfg["whitelist"].get("trust_minutes", 30))
            with self.lock:
                self.trusted_ips[flow["remote_ip"]] = time.time() + minutes * 60
                for f in self.flows.values():
                    if f["remote_ip"] == flow["remote_ip"]:
                        f["status"] = "trusted"
                self.pending.pop(alert_id, None)
            self.db.update_event_state(alert["event_id"], "continued", "continue")
            self.db.add_decision(alert["event_id"], "continue")
            self.log.info("机主选择继续连接：%s -> %s（已解除拦截，%.0f 分钟内不再提示）",
                          flow.get("process"), flow.get("remote_ip"), minutes)
            result = {"ok": True, "decision": "continue"}
        elif decision in ("block", "disconnect"):
            with self.lock:
                for f in self.flows.values():
                    if f["remote_ip"] == flow["remote_ip"] and f["process"] == flow.get("process"):
                        f["status"] = "blocked"
                self.pending.pop(alert_id, None)
            self.db.update_event_state(alert["event_id"], "blocked", "block")
            self.db.add_decision(alert["event_id"], "block")
            self.log.info("机主选择断开：%s -> %s（保持拦截）", flow.get("process"), flow.get("remote_ip"))
            result = {"ok": True, "decision": "block"}
        else:
            return {"ok": False, "error": f"未知决策: {decision}"}

        self._persist(force=True)
        return result

    # ------------------------------------------------------------------ 控件
    def control(self, action: str, **kw) -> Dict[str, Any]:
        if action == "kill_switch_on":
            res = self.fw.kill_switch(True)
            ok = res.get("ok", False)
            with self.lock:
                self.kill_switch = bool(ok)
            self.state["kill_switch"] = bool(ok)
            self._make_event(
                kind="control", level="high", score=60,
                title="已开启全局断流" if ok else "开启全局断流失败",
                detail=kw.get("reason") or ("已阻断全部公网出站" if ok else (res.get("hint") or "需要管理员权限")),
                action="block", state="done" if ok else "failed",
            )
            self._persist(force=True)
            return {"ok": ok, "kill_switch": self.kill_switch,
                    "hint": None if ok else (res.get("hint") or "需要管理员权限")}
        if action == "kill_switch_off":
            res = self.fw.kill_switch(False)
            with self.lock:
                self.kill_switch = False
            self.state["kill_switch"] = False
            self._make_event(kind="control", level="info", score=0,
                             title="已恢复网络（关闭全局断流）", detail="", action="alert", state="done")
            self._persist(force=True)
            return {"ok": True, "kill_switch": False}
        if action == "clear_blocks":
            res = self.fw.clear_all()
            with self.lock:
                self.blocked.clear()
                self.pending.clear()
                for f in self.flows.values():
                    if f["status"] in ("blocked", "pending"):
                        f["status"] = "normal"
            self._persist(force=True)
            return {"ok": True, "cleared": True}
        if action == "unblock":
            name = kw.get("name") or ""
            res = self.fw.unblock(name)
            with self.lock:
                self.blocked.pop(name, None)
            self._persist(force=True)
            return {"ok": res.get("ok", False)}
        if action == "update_geoip":
            return self.update_geoip()
        if action == "clear_events":
            with self.lock:
                self.events.clear()
            return {"ok": True}
        if action == "shutdown":
            if callable(self.on_shutdown):
                self.on_shutdown()
            return {"ok": True, "message": "正在退出"}
        return {"ok": False, "error": f"未知操作 {action}"}

    # ------------------------------------------------------------------ IP 库
    @staticmethod
    def _maxmind_key(cfg: Dict[str, Any]) -> str:
        return (os.environ.get("MAXMIND_LICENSE_KEY")
                or str(cfg["geoip"].get("maxmind_license_key") or "")).strip()

    def _fetch_official_geoip(self, key: str) -> bytes:
        """从 MaxMind 官方下载 GeoLite2（需 License Key），返回 mmdb 字节。"""
        import io
        import tarfile
        import urllib.parse
        import urllib.request

        url = ("https://download.maxmind.com/app/geoip_download"
               f"?edition_id=GeoLite2-Country&license_key={urllib.parse.quote(key)}&suffix=tar.gz")
        req = urllib.request.Request(url, headers={"User-Agent": f"TrafficGuard/{VERSION}"})
        with urllib.request.urlopen(req, timeout=180) as resp:
            raw = resp.read()
        if len(raw) < 100_000:
            raise ValueError("官方下载内容过小，可能 License Key 无效")
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
            member = next((m for m in tar.getmembers()
                           if m.name.endswith("GeoLite2-Country.mmdb")), None)
            if member is None:
                raise ValueError("压缩包内未找到 GeoLite2-Country.mmdb")
            fh = tar.extractfile(member)
            if fh is None:
                raise ValueError("压缩包读取失败")
            return fh.read()

    def _install_geoip(self, blob: bytes, target) -> Dict[str, Any]:
        tmp = target.with_suffix(".tmp")
        tmp.write_bytes(blob)
        tmp.replace(target)
        if self.geo.reload():
            self.log.info("GeoIP 数据库已更新: %s（%d 字节）", target, len(blob))
            self._refresh_geo_flows()
            return {"ok": True, "size": len(blob), "path": str(target)}
        raise ValueError(self.geo.error or "新库加载失败")

    def _refresh_geo_flows(self) -> None:
        """IP 库就绪/更新后，立刻重新解析所有流的归属，避免残留「未知地区」。"""
        with self.lock:
            for f in self.flows.values():
                geo = self.geo.lookup(f["remote_ip"])
                f["country"] = geo.get("country_cn") or ""
                f["country_cn"] = geo.get("country_cn") or ""
                f["iso"] = geo.get("iso") or ""
                f["scope"] = geo.get("scope") or "UNKNOWN"
                f["risk_evaluated"] = False

    def update_geoip(self) -> Dict[str, Any]:
        import urllib.request
        target = resolve_path(self.cfg["geoip"]["db_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        last_err = None

        # 1) 优先使用官方直链（需要 MaxMind License Key）
        key = self._maxmind_key(self.cfg)
        if key:
            try:
                return self._install_geoip(self._fetch_official_geoip(key), target)
            except Exception as exc:  # noqa: BLE001
                last_err = f"官方下载失败: {exc}"

        # 2) 回退到配置里的第三方镜像
        urls = [self.cfg["geoip"].get("download_url")] + list(self.cfg["geoip"].get("mirror_urls") or [])
        for url in [u for u in urls if u]:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": f"TrafficGuard/{VERSION}"})
                with urllib.request.urlopen(req, timeout=90) as resp:
                    data = resp.read()
                if len(data) < 1_000_000:
                    raise ValueError("下载内容异常（过小）")
                return self._install_geoip(data, target)
            except Exception as exc:  # noqa: BLE001
                last_err = f"{url}: {exc}"
        return {"ok": False, "error": last_err or "没有可用的下载地址"}

    # ------------------------------------------------------------------ 快照
    def status(self) -> Dict[str, Any]:
        with self.lock:
            flows = list(self.flows.values())
            pending = [self._alert_public(a) for a in self.pending.values()]
            t = dict(self.state.get("totals", {}))
            overseas = sum(1 for f in flows if f["scope"] == "OVERSEAS")
            hmt = sum(1 for f in flows if f["scope"] == "HMT")
            unknown = sum(1 for f in flows if f["scope"] == "UNKNOWN")
            lan = sum(1 for f in flows if f["scope"] == "LAN")
            high = sum(1 for f in flows if f["level"] == "high")
            quota = self._quota_info(t)
            return {
                "app": {
                    "name": "流量哨兵", "version": VERSION,
                    "uptime": int(time.time() - self.started_at),
                    "started_at": self.started_at, "admin": self.admin,
                    "firewall_ok": bool(self.admin and self.fw_ready),
                    "firewall_error": self.fw.last_error,
                    "simulate": self.fw.simulate,
                },
                "net": {
                    "rx_rate": self.rates["rx"], "tx_rate": self.rates["tx"],
                    "session_rx": self.session_total["rx"], "session_tx": self.session_total["tx"],
                    "day_in": t.get("day_in", 0), "day_out": t.get("day_out", 0),
                    "month_in": t.get("month_in", 0), "month_out": t.get("month_out", 0),
                    "interfaces": self._iface_public(),
                },
                "policy": {
                    "mode": self.cfg["policy"]["mode"],
                    "auto_block_enabled": self.cfg["policy"]["auto_block_enabled"],
                    "auto_block_threshold": self.cfg["policy"]["auto_block_threshold"],
                    "alert_threshold": self.cfg["policy"]["alert_threshold"],
                    "block_scope": self.cfg["policy"]["block_scope"],
                    "alert_timeout_sec": self.cfg["policy"]["alert_timeout_sec"],
                },
                "geo": self.geo.info(),
                "risk": self._risk_summary(pending),
                "counts": {
                    "flows": len(flows) - lan, "all_flows": len(flows), "overseas": overseas,
                    "hmt": hmt, "unknown": unknown, "lan": lan, "high_risk": high,
                    "blocked_rules": len(self.blocked), "pending_alerts": len(pending),
                    "events": len(self.events), "suppressed": self.suppressed,
                },
                "kill_switch": self.kill_switch,
                "quota": quota,
                "alerts": pending,
                "blocked": list(self.blocked.values()),
                "tick": self.tick_count, "ts": time.time(),
            }

    def _risk_summary(self, pending: List[Dict[str, Any]]) -> Dict[str, Any]:
        """整机风险 = 环境发现 + 近 24h 高危事件（含待处理提醒）。"""
        now = time.time()
        recent_high = sum(
            1 for e in list(self.events)[:200]
            if e.get("level") == "high" and now - float(e.get("ts", 0)) < 86400
        )
        risk = {
            "score": int(self.env.get("score", 0)),
            "level": self.env.get("level", "low"),
            "level_cn": self.env.get("level_cn", "低"),
            "findings": list(self.env.get("findings") or []),
            "disclaimer": self.env.get("disclaimer", DISCLAIMER),
        }
        if recent_high or pending:
            risk["score"] = min(100, risk["score"] + 20)
            risk["findings"].insert(0, {
                "kind": "recent_events", "level": "medium", "score": 20,
                "title": "近 24 小时出现过高风险连接",
                "detail": f"高危事件 {recent_high} 条，待机主处理 {len(pending)} 条",
                "advice": "相关连接已被截流；若频繁出现，说明本机可能正在使用跨境通道。",
            })
            risk["level"], risk["level_cn"] = level_of(risk["score"])
        return risk

    def _quota_info(self, t: Dict[str, Any]) -> Dict[str, Any]:
        q = self.cfg["quota"]
        day_used = t.get("day_in", 0) + t.get("day_out", 0)
        mon_used = t.get("month_in", 0) + t.get("month_out", 0)
        dlim = float(q.get("daily_gb") or 0) * 1024 ** 3
        mlim = float(q.get("monthly_gb") or 0) * 1024 ** 3
        return {
            "enabled": bool(q.get("enabled")), "daily_gb": float(q.get("daily_gb") or 0),
            "monthly_gb": float(q.get("monthly_gb") or 0),
            "warn_percent": q.get("warn_percent", 90),
            "day_used": day_used, "month_used": mon_used,
            "day_percent": round(day_used / dlim * 100, 1) if dlim else 0,
            "month_percent": round(mon_used / mlim * 100, 1) if mlim else 0,
        }

    def _iface_public(self) -> List[Dict[str, Any]]:
        kws = [k.lower() for k in (self.cfg["proxy"].get("vpn_adapter_keywords") or [])]
        out = []
        for a in self.iface_adapters:
            if a.get("is_filter") or (a.get("rx", 0) + a.get("tx", 0)) == 0:
                continue
            text = f'{a.get("name","")} {a.get("desc","")}'.lower()
            out.append({
                "name": a.get("name"), "desc": a.get("desc"), "mac": a.get("mac"),
                "speed": a.get("speed"), "rx": a.get("rx"), "tx": a.get("tx"),
                "virtual": any(k in text for k in kws) if kws else False,
            })
        out.sort(key=lambda x: (x["rx"] + x["tx"]), reverse=True)
        return out[:12]

    def _alert_public(self, a: Dict[str, Any]) -> Dict[str, Any]:
        f = a["flow"]
        return {
            "id": a["id"], "created": a["created"], "deadline": a["deadline"],
            "status": a["status"], "risk": a["risk"],
            "flow": {
                "process": f.get("process"), "pid": f.get("pid"),
                "app": f.get("app") or "",
                "remote_ip": f.get("remote_ip"), "remote_port": f.get("remote_port"),
                "country_cn": f.get("country_cn"), "iso": f.get("iso"),
                "scope": f.get("scope"), "proto": f.get("proto"),
            },
            "block": a.get("block_result"),
            "rule": a.get("rule"),
        }

    def flows_snapshot(self, limit: int = 300, sort: str = "risk",
                       include_lan: bool = False) -> Dict[str, Any]:
        """按「进程 + 远端 IP + 端口」聚合，避免同一目标的多条连接刷屏。"""
        with self.lock:
            raw = [dict(f) for f in self.flows.values()]
        agg: Dict[str, Dict[str, Any]] = {}
        for f in raw:
            if not include_lan and f["scope"] == "LAN":
                continue
            key = f'{f["process"]}|{f["remote_ip"]}|{f["remote_port"]}|{f["proto"]}'
            a = agg.get(key)
            if a is None:
                f.pop("exe", None)
                f["conns"] = 1
                a = agg[key] = f
            else:
                a["conns"] += 1
                a["rx"] += f["rx"]
                a["tx"] += f["tx"]
                a["rx_rate"] += f["rx_rate"]
                a["tx_rate"] += f["tx_rate"]
                a["last_seen"] = max(a["last_seen"], f["last_seen"])
                if f["score"] > a["score"]:
                    a["score"] = f["score"]
                    a["level"] = f["level"]
                    a["level_cn"] = f["level_cn"]
                    a["reasons"] = f["reasons"]
                    a["status"] = f["status"]
        items = list(agg.values())
        if sort == "traffic":
            items.sort(key=lambda x: (x["rx"] + x["tx"]), reverse=True)
        elif sort == "country":
            items.sort(key=lambda x: (x["scope"] != "DOMESTIC", x["score"], x["rx"] + x["tx"]), reverse=True)
        else:
            items.sort(key=lambda x: (x["score"], x["rx"] + x["tx"]), reverse=True)
        lan_conns = sum(1 for f in raw if f["scope"] == "LAN")
        return {"flows": items[:limit], "total": len(items), "lan_conns": lan_conns}

    def countries_snapshot(self) -> List[Dict[str, Any]]:
        with self.lock:
            agg: Dict[str, Dict[str, Any]] = {}
            for f in self.flows.values():
                key = f["iso"] or "??"
                a = agg.setdefault(key, {
                    "iso": f["iso"], "country_cn": f["country_cn"],
                    "scope": f["scope"], "flows": 0, "rx": 0.0, "tx": 0.0,
                    "risk_max": 0, "processes": set(),
                })
                a["flows"] += 1
                a["rx"] += f["rx"]
                a["tx"] += f["tx"]
                a["risk_max"] = max(a["risk_max"], f["score"])
                if f["process"]:
                    a["processes"].add(f["process"])
        total = sum(a["rx"] + a["tx"] for a in agg.values()) or 1
        out = []
        for a in agg.values():
            a["processes"] = sorted(a["processes"])[:6]
            a["percent"] = round((a["rx"] + a["tx"]) / total * 100, 1)
            out.append(a)
        out.sort(key=lambda x: x["rx"] + x["tx"], reverse=True)
        return out

    def processes_snapshot(self) -> List[Dict[str, Any]]:
        with self.lock:
            agg: Dict[str, Dict[str, Any]] = {}
            for f in self.flows.values():
                name = f["process"] or f"PID {f['pid']}"
                a = agg.setdefault(name, {
                    "process": name, "pid": f["pid"], "flows": 0, "rx": 0.0, "tx": 0.0,
                    "risk_max": 0, "countries": set(),
                    "app": f.get("app") or "", "app_company": f.get("app_company") or "",
                })
                a["flows"] += 1
                a["rx"] += f["rx"]
                a["tx"] += f["tx"]
                a["risk_max"] = max(a["risk_max"], f["score"])
                if f["country_cn"]:
                    a["countries"].add(f["country_cn"])
        out = []
        for a in agg.values():
            a["countries"] = sorted(a["countries"])[:5]
            out.append(a)
        out.sort(key=lambda x: x["rx"] + x["tx"], reverse=True)
        return out

    def events_snapshot(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.lock:
            mem = list(self.events)[:limit]
        if len(mem) >= limit:
            return mem
        try:
            db_events = self.db.list_events(limit)
        except Exception:  # noqa: BLE001
            db_events = []
        seen = {e["id"] for e in mem}
        return mem + [e for e in db_events if e["id"] not in seen][: max(0, limit - len(mem))]

    def config_snapshot(self) -> Dict[str, Any]:
        return {"config": self.cfg}

    def update_config(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        cfg = save_config(patch)
        self.cfg = cfg
        self.risk_engine = self._build_risk_engine()
        # GeoIP 相关设置变化时重载
        try:
            self.geo = GeoResolver(
                resolve_path(cfg["geoip"]["db_path"]),
                home_country=cfg["policy"]["home_country"],
                hmt_as_domestic=bool(cfg["policy"].get("hmt_as_domestic")),
            )
        except Exception:  # noqa: BLE001
            pass
        with self.lock:
            for f in self.flows.values():
                f["risk_evaluated"] = False
        return cfg

    def whitelist(self, kind: str, value: str, action: str) -> Dict[str, Any]:
        cfg = load_config(force=True)
        key = "processes" if kind == "process" else "ips"
        items = list(cfg["whitelist"].get(key) or [])
        if action == "add":
            if value and value not in items:
                items.append(value)
        else:
            items = [x for x in items if x != value]
        cfg = save_config({"whitelist": {key: items}})
        self.cfg = cfg
        self.risk_engine = self._build_risk_engine()
        with self.lock:
            for f in self.flows.values():
                f["risk_evaluated"] = False
        return {"ok": True, "items": items}

    # ------------------------------------------------------------------ 持久化
    def _persist(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_persist < 10:
            return
        self._last_persist = now
        with self.lock:
            self.state["blocked_rules"] = list(self.blocked.values())
            self.state["trusted_ips"] = {k: v for k, v in self.trusted_ips.items() if v > now}
            self.state["kill_switch"] = self.kill_switch
            snapshot = {
                "installed_at": self.state.get("installed_at", now),
                "trusted_ips": self.state["trusted_ips"],
                "blocked_rules": self.state["blocked_rules"],
                "kill_switch": self.kill_switch,
                "totals": self.state["totals"],
            }
            for k, v in self.state.items():
                if k.startswith("env_seen_") or k.startswith("quota_warn_"):
                    snapshot[k] = v
        try:
            save_state(snapshot)
        except Exception as exc:  # noqa: BLE001
            self.log.warning("保存状态失败: %s", exc)

    # ------------------------------------------------------------------ 弹窗线程
    def _alert_worker(self) -> None:
        while not self._stop.is_set():
            try:
                alert = self.alert_q.get(timeout=0.5)
            except queue.Empty:
                continue
            flow = alert["flow"]
            ip = flow.get("remote_ip") or ""
            proc = (flow.get("process") or "").lower()
            scope_any = self.cfg["policy"].get("block_scope") == "any"
            if proc in NEVER_BLOCK and not scope_any:
                proc_path = ""
            else:
                proc_path = flow.get("exe") or ""
            if proc in NEVER_BLOCK:
                block = {"ok": False, "hint": "系统关键进程不自动拦截，仅提示"}
            else:
                block = self.fw.block(
                    ip, "" if scope_any else proc_path,
                    note=f'{flow.get("process","")} 风险{flow.get("score",0)}',
                )
            with self.lock:
                if block.get("ok"):
                    alert["rule"] = block.get("name")
                    alert["status"] = "blocked"
                    self.blocked[block["name"]] = {
                        "name": block["name"], "ip": ip, "process": proc_path or "*",
                        "process_name": flow.get("process") or "", "created": time.time(),
                        "score": flow.get("score", 0),
                    }
                    for f in self.flows.values():
                        if f["remote_ip"] == ip and f["process"] == flow.get("process"):
                            f["status"] = "blocked"
                else:
                    alert["status"] = "block_pending"
                    self.block_failures += 1
                alert["block_result"] = {
                    "ok": bool(block.get("ok")), "hint": block.get("hint") or block.get("out"),
                }
                is_pending = alert["id"] in self.pending
            if block.get("ok"):
                self.db.update_event_state(alert["event_id"], "blocked", "block")
            if is_pending:
                self.popup_q.put({
                    "kind": "risk", "id": alert["id"], "title": "检测到高风险的跨境/境外连接",
                    "flow": alert["flow"], "risk": alert["risk"],
                    "block": alert["block_result"], "deadline": alert["deadline"],
                })
            self._persist(force=True)

