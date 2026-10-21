"""GeoIP 与 MMDB 解析测试。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from traffic_guard.geoip import GeoResolver, MMDBReader  # noqa: E402
from traffic_guard.config import load_config, resolve_path  # noqa: E402


class TestGeoIP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = load_config()
        cls.db = resolve_path(cfg["geoip"]["db_path"])
        cls.geo = GeoResolver(cls.db)
        if not cls.geo.available:
            raise unittest.SkipTest(f"缺少 GeoIP 数据库: {cls.geo.error}")

    def test_reader_metadata(self):
        self.assertIn("GeoLite2", self.geo.reader.database_type)
        self.assertGreater(self.geo.reader.node_count, 1000)

    def test_known_countries(self):
        cases = {
            "8.8.8.8": "US",
            "114.114.114.114": "CN",
            "223.5.5.5": "CN",
            "1.1.1.1": "AU",
            "17.253.144.10": "US",
        }
        for ip, iso in cases.items():
            self.assertEqual(self.geo.lookup(ip)["iso"], iso, ip)

    def test_scopes(self):
        self.assertEqual(self.geo.lookup("8.8.8.8")["scope"], "OVERSEAS")
        self.assertEqual(self.geo.lookup("114.114.114.114")["scope"], "DOMESTIC")
        self.assertEqual(self.geo.lookup("192.168.1.10")["scope"], "LAN")
        self.assertEqual(self.geo.lookup("127.0.0.1")["scope"], "LAN")

    def test_hmt_toggle(self):
        hk = "203.198.20.10"
        normal = GeoResolver(self.db, hmt_as_domestic=False).lookup(hk)
        domestic = GeoResolver(self.db, hmt_as_domestic=True).lookup(hk)
        if normal["iso"] == "HK":
            self.assertEqual(normal["scope"], "HMT")
            self.assertEqual(domestic["scope"], "DOMESTIC")

    def test_ipv6(self):
        r = self.geo.lookup("2606:4700:4700::1111")
        self.assertIn(r["iso"], ("US", "AU"))

    def test_cache(self):
        self.geo.lookup("9.9.9.9")
        self.assertIn("9.9.9.9", self.geo._cache)

    def test_blank_and_invalid(self):
        self.assertEqual(self.geo.lookup("")["scope"], "UNKNOWN")
        self.assertEqual(self.geo.lookup("不是IP")["scope"], "UNKNOWN")

    def test_reader_direct(self):
        r = MMDBReader(self.db)
        rec = r.lookup("8.8.8.8")
        self.assertIn("country", rec)


if __name__ == "__main__":
    unittest.main(verbosity=2)
