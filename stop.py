"""停止后台实例（读取 data/session.json 中的令牌调用本机 API）。"""
from __future__ import annotations

import json
import os
import signal
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SESSION = ROOT / "data" / "session.json"


def main() -> int:
    if not SESSION.exists():
        print("未找到会话文件，程序可能未在运行。")
        return 1
    try:
        info = json.loads(SESSION.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"会话文件损坏：{exc}")
        return 1

    url = f'http://{info.get("host", "127.0.0.1")}:{info["port"]}/api/control'
    req = urllib.request.Request(
        url, method="POST",
        data=json.dumps({"action": "shutdown"}).encode(),
        headers={"Content-Type": "application/json", "X-TG-Token": info["token"]},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print("已请求退出：", resp.read().decode("utf-8", "replace"))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"API 停止失败（{exc}），尝试结束进程 PID={info.get('pid')}")
    pid = int(info.get("pid") or 0)
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"已向 PID {pid} 发送结束信号。")
            return 0
        except Exception as exc:  # noqa: BLE001
            print(f"结束进程失败：{exc}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
