"""防火墙封装测试（全部走 simulate，不会真的改系统规则）。"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ["TG_SIMULATE"] = "1"

from traffic_guard.firewall import Firewall, KILL_RULE_V4, PUBLIC_V4_RANGES  # noqa: E402


class TestFirewall(unittest.TestCase):
    def setUp(self):
        self.fw = Firewall()

    def test_rule_name_is_stable_and_unique(self):
        a = Firewall.rule_name("blk", "1.2.3.4", "C:\\a.exe")
        b = Firewall.rule_name("blk", "1.2.3.4", "C:\\a.exe")
        c = Firewall.rule_name("blk", "1.2.3.4", "C:\\b.exe")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertTrue(a.startswith("TG-"))

    def test_block_with_process(self):
        res = self.fw.block("1.2.3.4", "C:\\Program Files\\x\\x.exe", "unit-test")
        self.assertTrue(res["ok"])
        cmd = self.fw.log[-1]["cmd"]
        self.assertIn("add rule", cmd)
        self.assertIn("remoteip=1.2.3.4", cmd)
        self.assertIn("program=C:\\Program Files\\x\\x.exe", cmd)
        self.assertIn("dir=out", cmd)
        self.assertIn("action=block", cmd)

    def test_block_without_process(self):
        res = self.fw.block("5.6.7.8", "", "no-program")
        self.assertTrue(res["ok"])
        self.assertNotIn("program=", self.fw.log[-1]["cmd"])

    def test_kill_switch_uses_public_ranges_only(self):
        self.fw.kill_switch(True)
        cmds = " ".join(x["cmd"] for x in self.fw.log)
        self.assertIn(KILL_RULE_V4, cmds)
        self.assertIn("1.0.0.0-9.255.255.255", cmds)
        # 私网段绝不能被封，否则会锁死本机局域网访问
        for private in ("10.0.0.0", "192.168.0.0", "172.16.0.0", "127.0.0.0"):
            self.assertNotIn(private, PUBLIC_V4_RANGES)

    def test_kill_switch_off(self):
        self.fw.kill_switch(False)
        cmds = " ".join(x["cmd"] for x in self.fw.log)
        self.assertIn("delete rule", cmds)

    def test_unblock(self):
        self.fw.unblock("TG-BLK-abc")
        self.assertIn("delete rule name=TG-BLK-abc", self.fw.log[-1]["cmd"])

    def test_blocking_ipv6(self):
        res = self.fw.block("2606:4700::1111", "", "v6")
        self.assertTrue(res["ok"])
        self.assertIn("2606:4700::1111", self.fw.log[-1]["cmd"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
