"""风险引擎单元测试：python -m unittest discover -s tests -v"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from traffic_guard.risk import RiskEngine, looks_like_proxy  # noqa: E402


POLICY_STD = {
    "mode": "standard", "auto_block_enabled": True, "auto_block_threshold": 70,
    "alert_threshold": 40, "home_country": "CN", "hmt_as_domestic": False,
}
PROXY = {
    "process_keywords": ["clash", "v2ray", "shadowsocks", "tor"],
    "local_listen_ports": [7890, 1080, 9050],
    "remote_ports": [9050, 8388, 1080, 51820],
    "vpn_adapter_keywords": ["tap-windows", "wireguard", "radmin vpn"],
}
WL = {"processes": [], "ips": []}


def flow(**kw):
    base = {"remote_ip": "1.2.3.4", "remote_port": 443, "proto": "TCP",
            "process": "chrome.exe", "exe": "C:\\chrome.exe", "state": "ESTABLISHED"}
    base.update(kw)
    return base


def geo(scope="OVERSEAS", iso="US", cn="美国"):
    return {"scope": scope, "iso": iso, "country_cn": cn}


class TestProxyDetection(unittest.TestCase):
    def test_matches_common_clients(self):
        for name in ("clash.exe", "Clash Verge.exe", "v2rayN.exe", "xray.exe",
                     "sing-box.exe", "ShadowsocksR.exe", "tor.exe", "wireguard.exe"):
            self.assertIsNotNone(looks_like_proxy(name), name)

    def test_no_false_positive_on_common_apps(self):
        for name in ("monitor.exe", "editor.exe", "chrome.exe", "steam.exe",
                     "explorer.exe", "Code.exe", "WeChat.exe", "System"):
            self.assertIsNone(looks_like_proxy(name), name)


class TestFlowScoring(unittest.TestCase):
    def setUp(self):
        self.eng = RiskEngine(POLICY_STD, PROXY, WL)

    def test_overseas_browser_is_not_blocked(self):
        r = self.eng.evaluate_flow(flow(), geo())
        self.assertGreaterEqual(r.score, 30)
        self.assertLess(r.score, 70)
        self.assertNotEqual(r.action, "block")

    def test_proxy_client_to_overseas_is_blocked(self):
        r = self.eng.evaluate_flow(flow(process="clash.exe"), geo())
        self.assertGreaterEqual(r.score, 70)
        self.assertEqual(r.action, "block")
        self.assertTrue(any("代理" in x for x in r.reasons))

    def test_tor_port_high_risk(self):
        r = self.eng.evaluate_flow(flow(process="unknown.exe", remote_port=9050), geo())
        self.assertGreaterEqual(r.score, 70)
        self.assertEqual(r.action, "block")

    def test_domestic_traffic_low_risk(self):
        r = self.eng.evaluate_flow(flow(remote_ip="114.114.114.114"), geo("DOMESTIC", "CN", "中国"))
        self.assertEqual(r.score, 0)
        self.assertEqual(r.action, "log")

    def test_hmt_is_cross_border_but_lower(self):
        r = self.eng.evaluate_flow(flow(), geo("HMT", "HK", "中国香港"))
        self.assertGreater(r.score, 0)
        self.assertLess(r.score, 35)

    def test_odd_port_adds_risk(self):
        base = self.eng.evaluate_flow(flow(remote_port=443), geo()).score
        odd = self.eng.evaluate_flow(flow(remote_port=4444), geo()).score
        self.assertGreater(odd, base)

    def test_whitelisted_ip_is_ignored(self):
        eng = RiskEngine(POLICY_STD, PROXY, {"processes": [], "ips": ["1.2.3.4"]})
        r = eng.evaluate_flow(flow(), geo())
        self.assertEqual(r.score, 0)

    def test_whitelisted_process_is_ignored(self):
        eng = RiskEngine(POLICY_STD, PROXY, {"processes": ["chrome.exe"], "ips": []})
        r = eng.evaluate_flow(flow(process="chrome.exe"), geo())
        self.assertEqual(r.score, 0)

    def test_foreign_dns_flagged(self):
        r = self.eng.evaluate_flow(flow(remote_ip="8.8.8.8", remote_port=53,
                                        process="svchost.exe"), geo())
        self.assertGreaterEqual(r.score, 50)

    def test_monitor_mode_never_blocks(self):
        eng = RiskEngine({**POLICY_STD, "mode": "monitor"}, PROXY, WL)
        r = eng.evaluate_flow(flow(process="clash.exe"), geo())
        self.assertEqual(r.action, "alert")

    def test_strict_mode_blocks_medium(self):
        eng = RiskEngine({**POLICY_STD, "mode": "strict"}, PROXY, WL)
        r = eng.evaluate_flow(flow(remote_port=4444), geo())
        self.assertGreaterEqual(r.score, 40)
        self.assertEqual(r.action, "block")

    def test_levels(self):
        self.assertEqual(self.eng.evaluate_flow(flow(process="clash.exe"), geo()).level, "high")
        self.assertEqual(self.eng.evaluate_flow(flow(), geo("LAN", "--", "局域网")).level, "info")


class TestEnvironment(unittest.TestCase):
    def setUp(self):
        self.eng = RiskEngine(POLICY_STD, PROXY, WL)

    def test_proxy_listener_detected(self):
        env = self.eng.evaluate_environment(
            [{"local_ip": "127.0.0.1", "port": 7890, "pid": 100, "process": "clash.exe"}],
            [], [{"name": "clash.exe", "pid": 100}], None)
        self.assertGreater(env["score"], 0)
        self.assertTrue(any(f["kind"] == "proxy_listen" for f in env["findings"]))
        self.assertTrue(env["disclaimer"])

    def test_vpn_adapter_detected(self):
        env = self.eng.evaluate_environment(
            [], [{"name": "Radmin VPN", "desc": "Famatech Radmin VPN Ethernet Adapter"}],
            [], None)
        self.assertTrue(any(f["kind"] == "vpn_adapter" for f in env["findings"]))

    def test_clean_machine(self):
        env = self.eng.evaluate_environment([], [], [], None)
        self.assertEqual(env["score"], 0)
        self.assertEqual(env["findings"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
