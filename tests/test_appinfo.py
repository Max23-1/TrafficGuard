"""应用程序识别（进程 → 所属应用）测试。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from traffic_guard.appinfo import ALIAS, describe, read_version_info  # noqa: E402

SYSTEM32 = Path(r"C:\Windows\System32")


class TestAppInfo(unittest.TestCase):
    def test_alias_without_file(self):
        d = describe("", "msedge.exe")
        self.assertEqual(d["app"], "Microsoft Edge 浏览器")
        self.assertEqual(d["source"], "known")

    def test_alias_is_case_insensitive(self):
        self.assertEqual(describe("", "Weixin.exe")["app"], "微信")
        self.assertEqual(describe("", "AVP.EXE")["app"], "卡巴斯基安全软件")

    def test_system_process_alias(self):
        self.assertEqual(describe("", "svchost.exe")["app"], "Windows 服务宿主")

    def test_version_resource_read(self):
        exe = SYSTEM32 / "svchost.exe"
        if not exe.exists():
            self.skipTest("缺少 svchost.exe")
        info = read_version_info(str(exe))
        self.assertTrue(info.get("description") or info.get("product"), info)

    def test_unknown_exe_falls_back_to_version_info(self):
        exe = SYSTEM32 / "notepad.exe"
        if not exe.exists():
            self.skipTest("缺少 notepad.exe")
        d = describe(str(exe), "notepad.exe")
        # 记事本在中文系统上描述为「记事本」，英文系统为「Notepad」
        self.assertTrue(d["app"], d)
        self.assertIn(d["source"], ("version", "company"))

    def test_unknown_everything(self):
        d = describe("", "some-random-thing.exe")
        self.assertEqual(d["app"], "")
        self.assertEqual(d["source"], "none")

    def test_alias_table_has_core_entries(self):
        for name in ("msedge.exe", "chrome.exe", "wechat.exe", "explorer.exe"):
            self.assertIn(name, ALIAS)

    def test_company_fallback(self):
        # 没有描述/产品名时，用公司名兜底（这里构造一个不存在的路径，只验证分支不抛错）
        d = describe("", "")
        self.assertIsInstance(d, dict)
        self.assertIn("app", d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
