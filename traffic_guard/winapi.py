"""Windows 原生 API 封装（纯 ctypes，无第三方依赖）。

提供：
  * TCP/UDP 连接表（含所属 PID）
  * 网卡级收发字节计数（64 位，排除回环）
  * 进程映像路径 / 创建时间 / IO 计数
  * 管理员权限判断
"""
from __future__ import annotations

import ctypes
import re
import socket
import struct
import threading
import time
from ctypes import wintypes as w
from typing import Any, Dict, List, Optional, Tuple

from .appinfo import describe as describe_app

iphlpapi = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
shell32 = ctypes.WinDLL("shell32.dll")

AF_INET, AF_INET6 = 2, 23
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1

TCP_STATES = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
    6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING",
    10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}
TCP_STATE_CN = {
    "CLOSED": "已关闭", "LISTEN": "监听", "SYN_SENT": "发起连接", "SYN_RCVD": "半连接",
    "ESTABLISHED": "已连接", "FIN_WAIT1": "关闭等待1", "FIN_WAIT2": "关闭等待2",
    "CLOSE_WAIT": "被动关闭", "CLOSING": "正在关闭", "LAST_ACK": "最后确认",
    "TIME_WAIT": "等待超时", "DELETE_TCB": "已删除",
}

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", w.DWORD), ("dwLocalAddr", w.DWORD), ("dwLocalPort", w.DWORD),
        ("dwRemoteAddr", w.DWORD), ("dwRemotePort", w.DWORD), ("dwOwningPid", w.DWORD),
    ]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16), ("dwLocalScopeId", w.DWORD),
        ("dwLocalPort", w.DWORD), ("ucRemoteAddr", ctypes.c_ubyte * 16),
        ("dwRemoteScopeId", w.DWORD), ("dwRemotePort", w.DWORD),
        ("dwState", w.DWORD), ("dwOwningPid", w.DWORD),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwLocalAddr", w.DWORD), ("dwLocalPort", w.DWORD), ("dwOwningPid", w.DWORD)]


class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16), ("dwLocalScopeId", w.DWORD),
        ("dwLocalPort", w.DWORD), ("dwOwningPid", w.DWORD),
    ]


class MIB_IF_ROW2(ctypes.Structure):
    """注意：真实结构在部分系统上比本定义多 8 字节尾部字段，读取时 stride 用 1352。"""
    _fields_ = [
        ("InterfaceLuid", ctypes.c_ulonglong), ("InterfaceIndex", w.DWORD),
        ("InterfaceGuid", ctypes.c_ubyte * 16), ("Alias", w.WCHAR * 257),
        ("Description", w.WCHAR * 257),
        ("PhysicalAddressLength", w.ULONG), ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
        ("Mtu", w.ULONG), ("Type", w.ULONG), ("TunnelType", w.ULONG),
        ("MediaType", w.ULONG), ("PhysicalMediumType", w.ULONG), ("AccessType", w.ULONG),
        ("DirectionType", w.ULONG), ("InterfaceAndOperStatusFlags", ctypes.c_ubyte),
        ("OperStatus", w.ULONG), ("AdminStatus", w.ULONG), ("MediaConnectState", w.ULONG),
        ("NetworkGuid", ctypes.c_ubyte * 16), ("ConnectionType", w.ULONG),
        ("TransmitLinkSpeed", ctypes.c_ulonglong), ("ReceiveLinkSpeed", ctypes.c_ulonglong),
        ("InOctets", ctypes.c_ulonglong), ("InUcastPkts", ctypes.c_ulonglong),
        ("InNUcastPkts", ctypes.c_ulonglong), ("InDiscards", ctypes.c_ulonglong),
        ("InErrors", ctypes.c_ulonglong), ("InUnknownProtos", ctypes.c_ulonglong),
        ("InUcastOctets", ctypes.c_ulonglong), ("InMulticastOctets", ctypes.c_ulonglong),
        ("InBroadcastOctets", ctypes.c_ulonglong),
        ("OutOctets", ctypes.c_ulonglong), ("OutUcastPkts", ctypes.c_ulonglong),
        ("OutNUcastPkts", ctypes.c_ulonglong), ("OutDiscards", ctypes.c_ulonglong),
        ("OutErrors", ctypes.c_ulonglong), ("OutUcastOctets", ctypes.c_ulonglong),
        ("OutMulticastOctets", ctypes.c_ulonglong), ("OutBroadcastOctets", ctypes.c_ulonglong),
    ]


IF_ROW_STRIDE = 1352  # sizeof(MIB_IF_ROW2) on Win10/11 x64
IF_ROW_PARSED = ctypes.sizeof(MIB_IF_ROW2)

# 过滤层驱动（WFP / 杀软 / QoS / NDIS Capture）与物理网卡共享同一份计数，必须排除避免重复累加
_FILTER_LAYER = re.compile(
    r"-(wfp|kaspersky|qos|virtual wifi|native wifi|microsoft ndis|npcap|lightweight|scheduler)",
    re.IGNORECASE,
)


def is_filter_layer(alias: str, desc: str = "") -> bool:
    text = f"{alias or ''} {desc or ''}"
    if _FILTER_LAYER.search(text):
        return True
    return bool(re.search(r"-\d{4}$", alias or ""))


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong), ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong), ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong), ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", w.DWORD), ("dwHighDateTime", w.DWORD)]


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _u16_port(raw: int) -> int:
    return socket.ntohs(raw & 0xFFFF)


def _ipv4(raw: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", raw))


def _ipv6(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, bytes(raw))


def _table(func_name: str, cls: int, af: int) -> Tuple[bytes, int]:
    fn = getattr(iphlpapi, func_name)
    size = w.DWORD(0)
    fn(None, ctypes.byref(size), True, af, cls, 0)
    if size.value == 0:
        return b"", 0
    buf = ctypes.create_string_buffer(size.value + 64)
    ret = fn(buf, ctypes.byref(size), True, af, cls, 0)
    if ret != 0:
        raise OSError(f"{func_name} 失败，错误码 {ret}")
    num = ctypes.cast(buf, ctypes.POINTER(w.DWORD)).contents.value
    return buf.raw, num


def tcp_connections(include_listen: bool = True) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    # IPv4
    try:
        raw, num = _table("GetExtendedTcpTable", TCP_TABLE_OWNER_PID_ALL, AF_INET)
        step = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
        for i in range(num):
            row = MIB_TCPROW_OWNER_PID.from_buffer_copy(raw[4 + i * step: 4 + (i + 1) * step])
            state = TCP_STATES.get(row.dwState, str(row.dwState))
            if not include_listen and state == "LISTEN":
                continue
            out.append({
                "proto": "TCP", "af": 4,
                "local_ip": _ipv4(row.dwLocalAddr), "local_port": _u16_port(row.dwLocalPort),
                "remote_ip": _ipv4(row.dwRemoteAddr), "remote_port": _u16_port(row.dwRemotePort),
                "state": state, "pid": int(row.dwOwningPid),
            })
    except OSError:
        pass
    # IPv6
    try:
        raw, num = _table("GetExtendedTcpTable", TCP_TABLE_OWNER_PID_ALL, AF_INET6)
        step = ctypes.sizeof(MIB_TCP6ROW_OWNER_PID)
        for i in range(num):
            row = MIB_TCP6ROW_OWNER_PID.from_buffer_copy(raw[4 + i * step: 4 + (i + 1) * step])
            state = TCP_STATES.get(row.dwState, str(row.dwState))
            if not include_listen and state == "LISTEN":
                continue
            out.append({
                "proto": "TCP", "af": 6,
                "local_ip": _ipv6(row.ucLocalAddr), "local_port": _u16_port(row.dwLocalPort),
                "remote_ip": _ipv6(row.ucRemoteAddr), "remote_port": _u16_port(row.dwRemotePort),
                "state": state, "pid": int(row.dwOwningPid),
            })
    except OSError:
        pass
    return out


def udp_endpoints() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for af, struct_t in ((AF_INET, MIB_UDPROW_OWNER_PID), (AF_INET6, MIB_UDP6ROW_OWNER_PID)):
        try:
            raw, num = _table("GetExtendedUdpTable", UDP_TABLE_OWNER_PID, af)
        except OSError:
            continue
        step = ctypes.sizeof(struct_t)
        for i in range(num):
            row = struct_t.from_buffer_copy(raw[4 + i * step: 4 + (i + 1) * step])
            local_ip = _ipv4(row.dwLocalAddr) if af == AF_INET else _ipv6(row.ucLocalAddr)
            out.append({
                "proto": "UDP", "af": 4 if af == AF_INET else 6,
                "local_ip": local_ip, "local_port": _u16_port(row.dwLocalPort),
                "remote_ip": "", "remote_port": 0,
                "state": "LISTEN", "pid": int(row.dwOwningPid),
            })
    return out


def interface_stats() -> Dict[str, Any]:
    """汇总所有「已连接」网卡的收发字节；相同 MAC 的过滤层驱动只计一次。"""
    p = ctypes.c_void_p()
    ret = iphlpapi.GetIfTable2(ctypes.byref(p))
    if ret != 0:
        raise OSError(f"GetIfTable2 失败，错误码 {ret}")
    try:
        num = ctypes.cast(p, ctypes.POINTER(ctypes.c_uint32)).contents.value
        base = p.value + 8
        seen: Dict[str, Dict[str, Any]] = {}
        for i in range(num):
            blob = ctypes.string_at(base + i * IF_ROW_STRIDE, IF_ROW_PARSED)
            row = MIB_IF_ROW2.from_buffer_copy(blob)
            if row.OperStatus != 1 or row.Type == 24:  # 24 = software loopback
                continue
            alias = (row.Alias or "").strip()
            desc = (row.Description or "").strip()
            if is_filter_layer(alias, desc):
                continue
            mac = bytes(row.PhysicalAddress[: row.PhysicalAddressLength or 0])
            key = mac.hex() if mac and mac != b"\x00" * len(mac) else f"luid:{row.InterfaceLuid}"
            cur = seen.get(key)
            cand = {
                "name": alias, "desc": desc, "mac": mac.hex(":").upper(),
                "index": row.InterfaceIndex, "mtu": row.Mtu,
                "speed": max(row.ReceiveLinkSpeed, row.TransmitLinkSpeed),
                "rx": int(row.InOctets), "tx": int(row.OutOctets),
                "is_filter": "-" in alias and alias != desc,
            }
            if cur is None:
                seen[key] = cand
            else:
                # 同一物理网卡的过滤层：取计数更大的一份，优先取「非过滤」别名
                if cand["rx"] + cand["tx"] > cur["rx"] + cur["tx"]:
                    cand["is_filter"] = cur["is_filter"] and cand["is_filter"]
                    seen[key] = cand
                elif not cand["is_filter"] and cur["is_filter"]:
                    cur.update(name=cand["name"], desc=cand["desc"], is_filter=False)
        adapters = list(seen.values())
        rx = sum(a["rx"] for a in adapters)
        tx = sum(a["tx"] for a in adapters)
        # 虚拟网卡（VPN/TAP）单独标出，供风险判断使用
        return {"rx": rx, "tx": tx, "adapters": adapters, "ts": time.time()}
    finally:
        iphlpapi.FreeMibTable(p)


_pid_cache: Dict[int, Tuple[float, Dict[str, Any]]] = {}
_pid_lock = threading.Lock()
_PID_TTL = 300.0


def process_info(pid: int) -> Dict[str, Any]:
    """返回 {pid, name, exe, create_time}；无权限访问时返回占位信息。"""
    now = time.time()
    with _pid_lock:
        hit = _pid_cache.get(pid)
        if hit and now - hit[0] < _PID_TTL:
            return hit[1]

    info: Dict[str, Any] = {"pid": pid, "name": "", "exe": "", "create_time": 0.0, "system": False}
    if pid == 0:
        info.update(name="System Idle", exe="", system=True)
    elif pid == 4:
        info.update(name="System", exe="", system=True)
    else:
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if h:
            try:
                size = w.DWORD(32768)
                buf = ctypes.create_unicode_buffer(size.value)
                if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                    exe = buf.value
                    info["exe"] = exe
                    info["name"] = exe.rsplit("\\", 1)[-1]
                ft = FILETIME()
                ft2, ft3, ft4 = FILETIME(), FILETIME(), FILETIME()
                if kernel32.GetProcessTimes(h, ctypes.byref(ft), ctypes.byref(ft2),
                                            ctypes.byref(ft3), ctypes.byref(ft4)):
                    info["create_time"] = (ft.dwHighDateTime << 32 | ft.dwLowDateTime) / 1e7
            finally:
                kernel32.CloseHandle(h)
        if not info["name"]:
            info["name"] = f"PID {pid}"

    # 「这个进程属于哪个应用程序」：优先中文别名，其次 exe 版本资源
    try:
        app = describe_app(info.get("exe", ""), info.get("name", ""))
        info["app"] = app.get("app") or ""
        info["app_product"] = app.get("product") or ""
        info["app_company"] = app.get("company") or ""
    except Exception:  # noqa: BLE001
        info["app"] = ""
        info["app_product"] = ""
        info["app_company"] = ""

    with _pid_lock:
        if len(_pid_cache) > 4096:
            _pid_cache.clear()
        _pid_cache[pid] = (now, info)
    return info


def process_io(pid: int) -> Optional[Tuple[int, int]]:
    """进程累计 IO 传输字节 (读, 写)。含磁盘 IO，仅用于估算网络占用。"""
    if pid <= 0:
        return None
    if pid == 4:
        # PID 4 无法用常规方式打开，退回全局尝试
        pass
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        io = IO_COUNTERS()
        if kernel32.GetProcessIoCounters(h, ctypes.byref(io)):
            return int(io.ReadTransferCount), int(io.WriteTransferCount)
    finally:
        kernel32.CloseHandle(h)
    return None


def clear_process_cache() -> None:
    with _pid_lock:
        _pid_cache.clear()


def local_addresses() -> List[str]:
    """本机所有网卡 IP（用于判断「连接到本机」的流量）。"""
    addrs: List[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip not in addrs:
                addrs.append(ip)
    except OSError:
        pass
    for a in ("127.0.0.1", "::1"):
        if a not in addrs:
            addrs.append(a)
    return addrs


_psapi = ctypes.WinDLL("psapi.dll")


def list_pids() -> List[int]:
    arr = (w.DWORD * 4096)()
    needed = w.DWORD(0)
    if not _psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(needed)):
        return []
    n = needed.value // ctypes.sizeof(w.DWORD)
    return [int(arr[i]) for i in range(n) if arr[i]]


def system_proxy() -> Dict[str, Any]:
    """读取 WinINET 系统代理设置。"""
    out = {"enabled": False, "server": "", "bypass": ""}
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
            try:
                val, _ = winreg.QueryValueEx(key, "ProxyEnable")
                out["enabled"] = bool(val)
            except OSError:
                pass
            try:
                out["server"], _ = winreg.QueryValueEx(key, "ProxyServer")
            except OSError:
                pass
            try:
                out["bypass"], _ = winreg.QueryValueEx(key, "ProxyOverride")
            except OSError:
                pass
    except OSError:
        pass
    if not out["server"]:
        out["enabled"] = False
    return out


def firewall_available() -> bool:
    """检测 MpsSvc / BFE 是否运行（防火墙服务被停用时 netsh 规则无效）。"""
    try:
        import subprocess
        for svc in ("MpsSvc", "BFE"):
            r = subprocess.run(["sc", "query", svc], capture_output=True, text=True,
                               encoding="mbcs", errors="replace", timeout=5)
            if "RUNNING" not in (r.stdout or "").upper():
                return False
        return True
    except Exception:  # noqa: BLE001
        return True
