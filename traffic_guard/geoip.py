"""离线 GeoIP 解析（MaxMind DB 格式的纯 Python 读取器，无第三方依赖）。

GeoLite2-Country.mmdb 结构：
  [ 二叉搜索树 | 16 字节分隔符 | 数据段 | 元数据标记 + 元数据 map ]
"""
from __future__ import annotations

import ipaddress
import struct
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"

# MMDB 数据类型
_T_POINTER, _T_UTF8, _T_DOUBLE, _T_BYTES = 1, 2, 3, 4
_T_UINT16, _T_UINT32, _T_MAP, _T_INT32 = 5, 6, 7, 8
_T_UINT64, _T_UINT128, _T_ARRAY, _T_CACHE = 9, 10, 11, 12
_T_END, _T_BOOL, _T_FLOAT = 13, 14, 15


class MMDBError(Exception):
    pass


class MMDBReader:
    """最小实现的 MaxMind DB 读取器，只做「IP -> 数据 map」查询。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._buf = self.path.read_bytes()
        self._load_metadata()

    # ------------------------------------------------------------ 元数据
    def _load_metadata(self) -> None:
        idx = self._buf.rfind(METADATA_MARKER)
        if idx < 0:
            raise MMDBError("不是有效的 MMDB 文件（找不到元数据标记）")
        meta, _ = self._decode(self._buf, idx + len(METADATA_MARKER), 0)
        if not isinstance(meta, dict):
            raise MMDBError("元数据解析失败")
        self.metadata: Dict[str, Any] = meta
        self.node_count = int(meta["node_count"])
        self.record_size = int(meta["record_size"])
        if self.record_size not in (24, 28, 32):
            raise MMDBError(f"不支持的 record_size: {self.record_size}")
        self.ip_version = int(meta.get("ip_version", 6))
        self.node_bytes = self.record_size // 4  # 每个节点左+右两条记录
        self.tree_size = self.node_count * self.node_bytes
        self.data_section_start = self.tree_size + 16
        self.database_type = str(meta.get("database_type", ""))

    # ------------------------------------------------------------ 解码
    def _decode(self, buf: bytes, offset: int, depth: int = 0) -> Tuple[Any, int]:
        if depth > 64:
            raise MMDBError("数据嵌套过深")
        ctrl = buf[offset]
        offset += 1
        type_num = ctrl >> 5
        if type_num == 0:  # 扩展类型
            type_num = 7 + buf[offset]
            offset += 1
        size = ctrl & 0x1F
        if type_num != _T_POINTER:
            if size == 29:
                size = 29 + buf[offset]
                offset += 1
            elif size == 30:
                size = 285 + int.from_bytes(buf[offset:offset + 2], "big")
                offset += 2
            elif size == 31:
                size = 65821 + int.from_bytes(buf[offset:offset + 3], "big")
                offset += 3

        if type_num == _T_POINTER:
            psize = ((ctrl >> 3) & 0x03) + 1
            raw = int.from_bytes(buf[offset:offset + psize], "big")
            offset += psize
            if psize == 1:
                ptr = ((ctrl & 0x07) << 8) | raw
            elif psize == 2:
                ptr = ((ctrl & 0x07) << 16) | raw
                ptr += 2048
            elif psize == 3:
                ptr = ((ctrl & 0x07) << 24) | raw
                ptr += 526336
            else:
                ptr = raw
            value, _ = self._decode(buf, self.data_section_start + ptr, depth + 1)
            return value, offset

        if type_num == _T_UTF8:
            return buf[offset:offset + size].decode("utf-8", "replace"), offset + size
        if type_num == _T_DOUBLE:
            return struct.unpack(">d", buf[offset:offset + 8])[0], offset + 8
        if type_num == _T_FLOAT:
            return struct.unpack(">f", buf[offset:offset + 4])[0], offset + 4
        if type_num == _T_BYTES:
            return buf[offset:offset + size], offset + size
        if type_num == _T_UINT16:
            return int.from_bytes(buf[offset:offset + size], "big"), offset + size
        if type_num == _T_UINT32:
            return int.from_bytes(buf[offset:offset + size], "big"), offset + size
        if type_num == _T_INT32:
            return int.from_bytes(buf[offset:offset + size], "big", signed=True), offset + size
        if type_num == _T_UINT64:
            return int.from_bytes(buf[offset:offset + size], "big"), offset + size
        if type_num == _T_UINT128:
            return int.from_bytes(buf[offset:offset + size], "big"), offset + size
        if type_num == _T_BOOL:
            return size != 0, offset
        if type_num == _T_MAP:
            out: Dict[Any, Any] = {}
            for _ in range(size):
                key, offset = self._decode(buf, offset, depth + 1)
                val, offset = self._decode(buf, offset, depth + 1)
                out[key] = val
            return out, offset
        if type_num == _T_ARRAY:
            arr = []
            for _ in range(size):
                val, offset = self._decode(buf, offset, depth + 1)
                arr.append(val)
            return arr, offset
        if type_num == _T_END:
            return None, offset
        if type_num == _T_CACHE:
            return None, offset + size
        raise MMDBError(f"未知数据类型 {type_num}")

    # ------------------------------------------------------------ 查询
    def _record(self, node: int, bit: int) -> int:
        base = node * self.node_bytes
        buf = self._buf
        if self.record_size == 24:
            off = base + bit * 3
            return int.from_bytes(buf[off:off + 3], "big")
        if self.record_size == 28:
            if bit == 0:
                return int.from_bytes(buf[base:base + 3], "big") + ((buf[base + 3] >> 4) << 24)
            return int.from_bytes(buf[base + 4:base + 7], "big") + ((buf[base + 3] & 0x0F) << 24)
        off = base + bit * 4
        return int.from_bytes(buf[off:off + 4], "big")

    def _lookup_bytes(self, ip_bytes: bytes) -> Optional[Dict[str, Any]]:
        node = 0
        total_bits = len(ip_bytes) * 8
        for i in range(total_bits):
            byte = ip_bytes[i >> 3]
            bit = (byte >> (7 - (i & 7))) & 1
            node = self._record(node, bit)
            if node == self.node_count:      # 空记录
                return None
            if node > self.node_count:       # 数据指针
                offset = node - self.node_count + self.tree_size
                value, _ = self._decode(self._buf, offset)
                return value if isinstance(value, dict) else None
        return None

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return None
        if addr.version == 4:
            if self.ip_version == 4:
                return self._lookup_bytes(addr.packed)
            return self._lookup_bytes(b"\x00" * 12 + addr.packed)
        return self._lookup_bytes(addr.packed)


class GeoResolver:
    """带 LRU 缓存的 Geo 查询封装，输出「国家/地区 + 是否海外」。"""

    # 英文国家名（GeoLite 提供英文），中文名通过常用映射表本地化
    CN_NAMES = {
        "CN": "中国", "HK": "中国香港", "MO": "中国澳门", "TW": "中国台湾",
        "US": "美国", "JP": "日本", "KR": "韩国", "SG": "新加坡", "GB": "英国",
        "DE": "德国", "FR": "法国", "CA": "加拿大", "AU": "澳大利亚", "RU": "俄罗斯",
        "NL": "荷兰", "SE": "瑞典", "CH": "瑞士", "IN": "印度", "BR": "巴西",
        "VN": "越南", "TH": "泰国", "MY": "马来西亚", "PH": "菲律宾", "ID": "印尼",
        "TR": "土耳其", "AE": "阿联酋", "IL": "以色列", "IT": "意大利", "ES": "西班牙",
        "PL": "波兰", "UA": "乌克兰", "IE": "爱尔兰", "FI": "芬兰", "NO": "挪威",
        "DK": "丹麦", "BE": "比利时", "AT": "奥地利", "CZ": "捷克", "RO": "罗马尼亚",
        "KZ": "哈萨克斯坦", "MN": "蒙古", "KP": "朝鲜", "MM": "缅甸", "LA": "老挝",
        "KH": "柬埔寨", "PK": "巴基斯坦", "BD": "孟加拉国", "IR": "伊朗", "SA": "沙特",
        "EG": "埃及", "ZA": "南非", "NG": "尼日利亚", "AR": "阿根廷", "CL": "智利",
        "MX": "墨西哥", "PE": "秘鲁", "CO": "哥伦比亚", "NZ": "新西兰", "PT": "葡萄牙",
        "GR": "希腊", "HU": "匈牙利", "BG": "保加利亚", "LT": "立陶宛", "LV": "拉脱维亚",
        "EE": "爱沙尼亚", "SK": "斯洛伐克", "SI": "斯洛文尼亚", "HR": "克罗地亚",
        "RS": "塞尔维亚", "BY": "白俄罗斯", "UZ": "乌兹别克斯坦", "TJ": "塔吉克斯坦",
        "KG": "吉尔吉斯斯坦", "TM": "土库曼斯坦", "AZ": "阿塞拜疆", "GE": "格鲁吉亚",
        "AM": "亚美尼亚", "CY": "塞浦路斯", "MT": "马耳他", "LU": "卢森堡", "IS": "冰岛",
        "QA": "卡塔尔", "KW": "科威特", "BH": "巴林", "OM": "阿曼", "JO": "约旦",
        "LB": "黎巴嫩", "IQ": "伊拉克", "SY": "叙利亚", "AF": "阿富汗", "NP": "尼泊尔",
        "LK": "斯里兰卡", "BT": "不丹", "MV": "马尔代夫", "BN": "文莱", "TL": "东帝汶",
        "PG": "巴布亚新几内亚", "FJ": "斐济", "GU": "关岛", "PR": "波多黎各",
    }

    def __init__(self, db_path: str | Path, home_country: str = "CN", hmt_as_domestic: bool = False):
        self.db_path = Path(db_path)
        self.home = (home_country or "CN").upper()
        self.hmt_as_domestic = hmt_as_domestic
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.reader: Optional[MMDBReader] = None
        self.error: Optional[str] = None
        self.loaded_at = 0.0
        self.reload()

    def reload(self) -> bool:
        try:
            self.reader = MMDBReader(self.db_path)
            self.error = None
            self.loaded_at = __import__("time").time()
            with self._lock:
                self._cache.clear()
            return True
        except Exception as exc:  # noqa: BLE001
            self.reader = None
            self.error = f"{type(exc).__name__}: {exc}"
            return False

    @property
    def available(self) -> bool:
        return self.reader is not None

    def info(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "path": str(self.db_path),
            "error": self.error,
            "database_type": self.reader.database_type if self.reader else None,
            "built_epoch": self._build_time(),
            "loaded_at": self.loaded_at,
            "cached": len(self._cache),
        }

    def _build_time(self) -> Optional[int]:
        if not self.reader:
            return None
        for key in ("build_epoch", "build_timestamp"):
            v = self.reader.metadata.get(key)
            if isinstance(v, int):
                return v
        return None

    def classify_country(self, cc: str) -> str:
        if not cc:
            return "UNKNOWN"
        if cc == self.home:
            return "DOMESTIC"
        if cc in ("HK", "MO", "TW"):
            return "DOMESTIC" if self.hmt_as_domestic else "HMT"
        return "OVERSEAS"

    def lookup(self, ip: str) -> Dict[str, Any]:
        with self._lock:
            hit = self._cache.get(ip)
            if hit is not None:
                return hit
        res: Dict[str, Any] = {
            "ip": ip, "country": "", "country_cn": "", "iso": "",
            "continent": "", "scope": "UNKNOWN", "known": False,
        }
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                res.update(country="LAN", country_cn="局域网", iso="--", scope="LAN", known=True)
                return self._remember(ip, res)
            if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
                res.update(country="RESERVED", country_cn="保留地址", iso="--", scope="LAN", known=True)
                return self._remember(ip, res)
        except ValueError:
            return res

        rec = None
        if self.reader is not None:
            try:
                rec = self.reader.lookup(ip)
            except Exception as exc:  # noqa: BLE001
                self.error = f"查询失败: {exc}"
                rec = None
        if rec:
            # 部分网段（Anycast / 代理注册）只有 registered_country，需要回退
            country = rec.get("country") or rec.get("registered_country") or {}
            iso = (country.get("iso_code") or "").upper()
            names = country.get("names") or {}
            continent = (rec.get("continent") or {}).get("code") or ""
            res.update(
                iso=iso,
                country=names.get("en") or iso or "",
                country_cn=self.CN_NAMES.get(iso) or names.get("zh-CN") or names.get("en") or iso or "未知",
                continent=continent,
                scope=self.classify_country(iso),
                known=bool(iso),
            )
        elif self.reader is None:
            # 数据库还没就绪（例如首次运行正在下载）：不要缓存「未知」，
            # 否则下载完成后这些 IP 会一直显示为未知地区。
            res.update(country="未知", country_cn="未知地区", iso="", scope="UNKNOWN", known=False)
            return res
        else:
            res.update(country="未知", country_cn="未知地区", iso="??", scope="UNKNOWN", known=False)
        return self._remember(ip, res)

    def _remember(self, ip: str, res: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if len(self._cache) > 20000:
                self._cache.clear()
            self._cache[ip] = res
        return res
