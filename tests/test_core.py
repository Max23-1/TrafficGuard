"""核心引擎集成测试：真实采样本机连接，但截流走模拟模式。"""
from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ["TG_SIMULATE"] = "1"

from traffic_guard.core import Guard  # noqa: E402


class TestCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g = Guard()
        for _ in range(3):
            cls.g.tick()
            time.sleep(1.1)

    @classmethod
    def tearDownClass(cls):
        cls.g.stop()

    def test_status_shape(self):
        st = self.g.status()
        for key in ("app", "net", "policy", "geo", "risk", "counts", "quota", "alerts"):
            self.assertIn(key, st)
        self.assertIn("rx_rate", st["net"])
        self.assertIn("disclaimer", st["risk"])
        self.assertGreaterEqual(st["net"]["session_rx"], 0)

    def test_flows_have_geo(self):
        data = self.g.flows_snapshot(limit=50)
        self.assertIn("flows", data)
        for f in data["flows"]:
            self.assertIn("country_cn", f)
            self.assertIn(f["scope"], ("OVERSEAS", "HMT", "DOMESTIC", "LAN", "UNKNOWN"))
            self.assertIn(f["level"], ("high", "medium", "low", "info"))
            self.assertGreaterEqual(f["conns"], 1)

    def test_lan_filtered_by_default(self):
        data = self.g.flows_snapshot(limit=200)
        self.assertFalse(any(f["scope"] == "LAN" for f in data["flows"]))
        data_lan = self.g.flows_snapshot(limit=200, include_lan=True)
        self.assertGreaterEqual(data_lan["lan_conns"], 0)

    def test_countries_and_processes(self):
        countries = self.g.countries_snapshot()
        self.assertIsInstance(countries, list)
        if countries:
            self.assertIn("percent", countries[0])
            self.assertGreaterEqual(countries[0]["percent"], 0)
        procs = self.g.processes_snapshot()
        self.assertIsInstance(procs, list)

    def test_kill_switch_simulated(self):
        res = self.g.control("kill_switch_on", reason="unit-test")
        self.assertTrue(res["ok"])
        self.assertTrue(res["kill_switch"])
        self.assertTrue(self.g.kill_switch)
        res2 = self.g.control("kill_switch_off")
        self.assertFalse(res2["kill_switch"])

    def test_decide_flow(self):
        # 构造一条高危流，验证「先截流后告知」与决策闭环
        now = time.time()
        key = "TCP|127.0.0.1:1|9.9.9.9:443|4242"
        flow = {
            "id": key, "proto": "TCP", "local_ip": "127.0.0.1", "local_port": 1,
            "remote_ip": "9.9.9.9", "remote_port": 443, "pid": 4242,
            "process": "clash.exe", "exe": "C:\\clash.exe", "state": "ESTABLISHED",
            "country": "美国", "country_cn": "美国", "iso": "US", "scope": "OVERSEAS",
            "score": 0, "level": "info", "level_cn": "正常", "reasons": [], "tags": [],
            "action": "log", "rx": 0.0, "tx": 0.0, "rx_rate": 0.0, "tx_rate": 0.0,
            "first_seen": now, "last_seen": now, "risk_evaluated": False, "status": "normal",
        }
        with self.g.lock:
            self.g.flows[key] = flow
        self.g._evaluate_flow(flow)
        self.assertGreaterEqual(flow["score"], 70)
        self.assertEqual(len(self.g.pending), 1)
        alert_id = next(iter(self.g.pending))
        res = self.g.decide(alert_id, "block")
        self.assertTrue(res["ok"])
        self.assertEqual(self.g.pending, {})

    def test_config_update(self):
        cfg = self.g.update_config({"policy": {"mode": "monitor"}})
        self.assertEqual(cfg["policy"]["mode"], "monitor")
        cfg = self.g.update_config({"policy": {"mode": "standard"}})
        self.assertEqual(cfg["policy"]["mode"], "standard")


if __name__ == "__main__":
    unittest.main(verbosity=2)
