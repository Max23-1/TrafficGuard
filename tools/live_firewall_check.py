"""实机验证（需要管理员）：真正写入防火墙规则，验证「截流 → 连接受阻 → 解除 → 恢复」。

用法（务必以管理员身份运行）：
    python tools/live_firewall_check.py

它会临时封锁一个可达的境外 IP，验证规则确实生效，然后立即删除规则；
全程约 20 秒，结束后不会留下任何防火墙规则。
"""
from __future__ import annotations

import json
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from traffic_guard import winapi as W  # noqa: E402
from traffic_guard.core import Guard  # noqa: E402
from traffic_guard.firewall import Firewall  # noqa: E402

RESULT = ROOT / "data" / "live_check_result.json"
steps: list[dict] = []
TARGET = ""

# 优先选「境外且可达」的目标，其次境内可达目标
FOREIGN_CANDIDATES = [
    "4.145.79.81", "20.42.73.26", "104.46.162.229", "17.253.144.10",
    "13.107.42.14", "104.16.0.1", "8.8.8.8", "1.1.1.1",
]
DOMESTIC_CANDIDATES = ["223.5.5.5", "180.101.50.242", "114.114.114.114", "119.29.29.29"]


def step(name: str, ok: bool, detail: str = "") -> None:
    steps.append({"name": name, "ok": bool(ok), "detail": str(detail)[:400]})


def probe(target: str, timeout: float = 5.0) -> bool:
    try:
        s = socket.create_connection((target, 443), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def pick_target() -> tuple[str, bool]:
    for cand in FOREIGN_CANDIDATES:
        if probe(cand, 4.0):
            return cand, True
    for cand in DOMESTIC_CANDIDATES:
        if probe(cand, 4.0):
            return cand, False
    return "", False


def main() -> int:
    global TARGET
    step("admin", W.is_admin())
    fw = Firewall(simulate=False)
    TARGET, foreign = pick_target()
    step("pick_target", bool(TARGET), f"{TARGET} (境外={foreign})")
    if not TARGET:
        raise RuntimeError("找不到可达的目标 IP，无法验证")

    # ---------- 1. 防火墙底层：加规则 -> 阻断 -> 删规则 -> 恢复 ----------
    step("baseline_connect", probe(TARGET), f"{TARGET}:443 拦截前可达")
    r1 = fw.block(TARGET, "", "live-verify")
    step("add_rule", r1.get("ok"), r1.get("out", ""))
    step("verify_rule", fw.verify(r1.get("name", "")), r1.get("name", ""))
    time.sleep(1.2)
    step("connect_blocked", not probe(TARGET), "规则生效后不可达")
    fw.unblock(r1.get("name", ""))
    time.sleep(1.2)
    step("recovered_after_unblock", probe(TARGET), "删除规则后恢复")

    # ---------- 2. 业务链路：高危流 -> 自动截流 -> 机主选择继续 ----------
    g = Guard()
    with g.lock:  # 清理上次运行遗留的信任记录，保证本次可触发告警
        g.trusted_ips.clear()
        g.trusted_procs.clear()
        g.blocked.clear()
        g.state["blocked_rules"] = []
        g.state["trusted_ips"] = {}
    g.start()
    now = time.time()
    key = f"TCP|127.0.0.1:1|{TARGET}:9050|9999"
    flow = {
        "id": key, "proto": "TCP", "local_ip": "127.0.0.1", "local_port": 1,
        "remote_ip": TARGET, "remote_port": 9050, "pid": 9999,
        "process": Path(sys.executable).name, "exe": sys.executable,
        "state": "ESTABLISHED", "country": "", "country_cn": "", "iso": "",
        "scope": "OVERSEAS", "score": 0, "level": "info", "level_cn": "正常",
        "reasons": [], "tags": [], "action": "log", "rx": 0.0, "tx": 0.0,
        "rx_rate": 0.0, "tx_rate": 0.0, "first_seen": now, "last_seen": now,
        "risk_evaluated": False, "status": "normal",
    }
    with g.lock:
        g.flows[key] = flow
    g._evaluate_flow(flow)
    step("risk_engine_block", flow["action"] == "block", f'score={flow["score"]}')

    deadline = time.time() + 8
    while time.time() < deadline and not g.pending:
        time.sleep(0.2)
    alert_id = next(iter(g.pending), "")
    step("alert_created", bool(alert_id), alert_id)
    time.sleep(1.5)
    alert = g.pending.get(alert_id) or {}
    step("alert_rule_written", bool(alert.get("rule")), str(alert.get("rule")))
    step("alert_status_blocked", alert.get("status") == "blocked", str(alert.get("status")))
    step("engine_block_effective", not probe(TARGET), "截流后不可达")

    decide = g.decide(alert_id, "continue")
    step("decide_continue", decide.get("ok", False), str(decide))
    time.sleep(1.5)
    step("recovered_after_continue", probe(TARGET), "机主选择继续后恢复")
    step("pending_cleared", not g.pending, "")

    # ---------- 3. 清理 ----------
    g.control("clear_blocks")
    time.sleep(0.6)
    leftovers = [x for x in fw.list_rules() if str(x.get("name", "")).startswith("TG-")]
    step("no_leftover_rules", len(leftovers) == 0, f"{len(leftovers)} 条残留")
    g.stop()

    ok = all(s["ok"] for s in steps)
    RESULT.write_text(json.dumps({"ok": ok, "steps": steps}, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        step("exception", False, f"{type(exc).__name__}: {exc}")
        RESULT.write_text(json.dumps({"ok": False, "steps": steps}, ensure_ascii=False, indent=2),
                          encoding="utf-8")
        sys.exit(2)
