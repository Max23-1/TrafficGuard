"""进程 → 所属应用程序。

优先使用 exe 内嵌的版本资源（FileDescription / ProductName / CompanyName），
再叠加一份常用程序的中文名表；两者都没有时退回「公司名 + 进程名」。
"""
from __future__ import annotations

import ctypes
import re
from ctypes import wintypes as w
from typing import Dict, Optional, Tuple

_version = ctypes.WinDLL("version.dll", use_last_error=True)

_version.GetFileVersionInfoSizeW.argtypes = [w.LPCWSTR, ctypes.POINTER(w.DWORD)]
_version.GetFileVersionInfoSizeW.restype = w.DWORD
_version.GetFileVersionInfoW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID]
_version.GetFileVersionInfoW.restype = w.BOOL
_version.VerQueryValueW.argtypes = [w.LPCVOID, w.LPCWSTR, ctypes.POINTER(ctypes.c_void_p),
                                    ctypes.POINTER(ctypes.c_uint)]
_version.VerQueryValueW.restype = w.BOOL

# 常见程序的中文显示名（版本资源里多为英文全称，这里给出更易识别的叫法）
ALIAS: Dict[str, str] = {
    "msedge.exe": "Microsoft Edge 浏览器",
    "chrome.exe": "Google Chrome 浏览器",
    "firefox.exe": "Mozilla Firefox 浏览器",
    "iexplore.exe": "Internet Explorer",
    "opera.exe": "Opera 浏览器",
    "brave.exe": "Brave 浏览器",
    "360se.exe": "360 安全浏览器",
    "360chrome.exe": "360 极速浏览器",
    "qqbrowser.exe": "QQ 浏览器",
    "sogouexplorer.exe": "搜狗浏览器",
    "2345explorer.exe": "2345 浏览器",
    "avp.exe": "卡巴斯基安全软件",
    "avpui.exe": "卡巴斯基安全软件",
    "msmpeng.exe": "Windows Defender",
    "360tray.exe": "360 安全卫士",
    "huorong.exe": "火绒安全",
    "usysdiag.exe": "火绒安全",
    "qqpctray.exe": "腾讯电脑管家",
    "onedrive.exe": "Microsoft OneDrive 云盘",
    "onedrive.sync.service.exe": "Microsoft OneDrive 云盘",
    "msedgewebview2.exe": "Microsoft Edge WebView2",
    "dropbox.exe": "Dropbox",
    "baidunetdisk.exe": "百度网盘",
    "aliyundrive.exe": "阿里云盘",
    "wechat.exe": "微信",
    "wechatappex.exe": "微信",
    "weixin.exe": "微信",
    "wechatservice.exe": "微信",
    "wxwork.exe": "企业微信",
    "qq.exe": "QQ",
    "tim.exe": "TIM",
    "dingtalk.exe": "钉钉",
    "feishu.exe": "飞书",
    "lark.exe": "飞书",
    "wemeetapp.exe": "腾讯会议",
    "zoom.exe": "Zoom",
    "telegram.exe": "Telegram",
    "discord.exe": "Discord",
    "whatsapp.exe": "WhatsApp",
    "line.exe": "LINE",
    "skype.exe": "Skype",
    "teams.exe": "Microsoft Teams",
    "ms-teams.exe": "Microsoft Teams",
    "outlook.exe": "Microsoft Outlook",
    "winword.exe": "Microsoft Word",
    "excel.exe": "Microsoft Excel",
    "powerpnt.exe": "Microsoft PowerPoint",
    "wps.exe": "WPS Office",
    "et.exe": "WPS 表格",
    "wpp.exe": "WPS 演示",
    "acrobat.exe": "Adobe Acrobat",
    "acrord32.exe": "Adobe Reader",
    "photoshop.exe": "Adobe Photoshop",
    "code.exe": "Visual Studio Code",
    "devenv.exe": "Visual Studio",
    "pycharm64.exe": "PyCharm",
    "idea64.exe": "IntelliJ IDEA",
    "goland64.exe": "GoLand",
    "webstorm64.exe": "WebStorm",
    "steam.exe": "Steam",
    "steamwebhelper.exe": "Steam",
    "epicgameslauncher.exe": "Epic Games",
    "battle.net.exe": "战网",
    "wegame.exe": "WeGame",
    "spotify.exe": "Spotify",
    "cloudmusic.exe": "网易云音乐",
    "qqmusic.exe": "QQ 音乐",
    "potplayermini64.exe": "PotPlayer",
    "vlc.exe": "VLC 播放器",
    "obs64.exe": "OBS Studio",
    "bilibili.exe": "哔哩哔哩",
    "douyin.exe": "抖音",
    "thunder.exe": "迅雷",
    "qbittorrent.exe": "qBittorrent",
    "utorrent.exe": "uTorrent",
    "anydesk.exe": "AnyDesk",
    "todesk.exe": "ToDesk",
    "sunloginclient.exe": "向日葵远程控制",
    "radmin.exe": "Radmin",
    "vmware-vmx.exe": "VMware",
    "virtualboxvm.exe": "VirtualBox",
    "explorer.exe": "Windows 资源管理器",
    "svchost.exe": "Windows 服务宿主",
    "system": "Windows 系统",
    "system idle": "Windows 空闲进程",
    "registry": "Windows 注册表",
    "memory compression": "Windows 内存压缩",
    "searchhost.exe": "Windows 搜索",
    "searchapp.exe": "Windows 搜索",
    "shellexperiencehost.exe": "Windows 开始菜单",
    "startmenuexperiencehost.exe": "Windows 开始菜单",
    "runtimebroker.exe": "Windows 运行时",
    "dwm.exe": "Windows 桌面窗口管理器",
    "lsass.exe": "Windows 本地安全认证",
    "csrss.exe": "Windows 客户端服务",
    "services.exe": "Windows 服务控制管理器",
    "wininit.exe": "Windows 启动初始化",
    "smss.exe": "Windows 会话管理",
    "taskhostw.exe": "Windows 任务宿主",
    "conhost.exe": "Windows 控制台宿主",
    "dllhost.exe": "Windows COM 代理",
    "backgroundtaskhost.exe": "Windows 后台任务",
    "python.exe": "Python",
    "pythonw.exe": "Python",
    "git.exe": "Git",
    "node.exe": "Node.js",
    "java.exe": "Java",
    "javaw.exe": "Java",
    "clash.exe": "Clash 代理客户端",
    "clash-win64.exe": "Clash 代理客户端",
    "mihomo.exe": "Mihomo 代理客户端",
    "v2rayn.exe": "v2rayN 代理客户端",
    "xray.exe": "Xray 代理客户端",
    "sing-box.exe": "sing-box 代理客户端",
    "shadowsocks.exe": "Shadowsocks 客户端",
    "warp-svc.exe": "Cloudflare WARP",
    "trafficguard.exe": "流量哨兵（本程序）",
}

# 公司名 → 更易读的品牌名
COMPANY_HINT = {
    "kaspersky": "卡巴斯基",
    "microsoft": "Microsoft",
    "google": "Google",
    "mozilla": "Mozilla",
    "tencent": "腾讯",
    "alibaba": "阿里巴巴",
    "bytedance": "字节跳动",
    "baidu": "百度",
    "netease": "网易",
    "adobe": "Adobe",
    "jetbrains": "JetBrains",
    "valve": "Valve",
    "wps": "金山办公",
    "kingsoft": "金山",
    "qihoo": "奇虎 360",
    "huorong": "火绒",
}

_cache: Dict[str, Dict[str, str]] = {}


def _query(block, sub: str) -> str:
    ptr = ctypes.c_void_p()
    size = ctypes.c_uint(0)
    try:
        ok = _version.VerQueryValueW(block, sub, ctypes.byref(ptr), ctypes.byref(size))
    except Exception:  # noqa: BLE001
        return ""
    if not ok or not size.value or not ptr.value:
        return ""
    raw = ctypes.wstring_at(ptr.value, size.value)
    return raw.rstrip("\x00").strip()


def _translations(block) -> list[tuple[int, int]]:
    ptr = ctypes.c_void_p()
    size = ctypes.c_uint(0)
    ok = _version.VerQueryValueW(block, "\\VarFileInfo\\Translation",
                                 ctypes.byref(ptr), ctypes.byref(size))
    if not ok or not size.value or not ptr.value:
        return []
    count = size.value // 2
    arr = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_uint16))
    langs = [(arr[i * 2], arr[i * 2 + 1]) for i in range(count)]
    # 中文优先，其次英文，最后第一个
    langs.sort(key=lambda lc: (0 if lc[0] == 0x0804 else 1 if lc[0] == 0x0409 else 2))
    return langs


def read_version_info(path: str) -> Dict[str, str]:
    """读取 exe 的版本资源，返回 {description, product, company, version}。"""
    if not path:
        return {}
    cached = _cache.get(path)
    if cached is not None:
        return cached
    info: Dict[str, str] = {}
    try:
        size = _version.GetFileVersionInfoSizeW(path, None)
        if size:
            buf = ctypes.create_string_buffer(size)
            if _version.GetFileVersionInfoW(path, 0, size, buf):
                for lang, cp in _translations(buf) or [(0x0409, 0x04B0)]:
                    prefix = f"\\StringFileInfo\\{lang:04x}{cp:04x}\\"
                    desc = _query(buf, prefix + "FileDescription")
                    prod = _query(buf, prefix + "ProductName")
                    comp = _query(buf, prefix + "CompanyName")
                    ver = _query(buf, prefix + "FileVersion")
                    if desc or prod or comp:
                        info = {"description": desc, "product": prod,
                                "company": comp, "version": ver}
                        break
    except Exception:  # noqa: BLE001
        info = {}
    if len(_cache) > 2048:
        _cache.clear()
    _cache[path] = info
    return info


def _clean(text: str) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    # 去掉「xxx Application」「xxx 应用程序」这类冗余后缀
    text = re.sub(r"\s*(Application|应用程序)$", "", text, flags=re.IGNORECASE)
    return text.strip()


def describe(exe_path: str, process_name: str = "") -> Dict[str, str]:
    """给出「这个进程属于哪个应用程序」。

    返回 {app: 展示名, product: 产品名, company: 公司, version: 版本, source: 来源}
    """
    name = (process_name or "").lower()
    if not name and exe_path:
        name = exe_path.rsplit("\\", 1)[-1].lower()

    if name in ALIAS:
        vinfo = read_version_info(exe_path) if exe_path else {}
        return {"app": ALIAS[name], "product": _clean(vinfo.get("product", "")),
                "company": _clean(vinfo.get("company", "")),
                "version": vinfo.get("version", ""), "source": "known"}

    vinfo = read_version_info(exe_path) if exe_path else {}
    desc = _clean(vinfo.get("description", ""))
    prod = _clean(vinfo.get("product", ""))
    comp = _clean(vinfo.get("company", ""))

    app = desc or prod
    source = "version" if app else ""
    if not app:
        # 公司名 + 进程名，例如 "Kaspersky Lab · avp.exe"
        brand = ""
        low = comp.lower()
        for key, cn in COMPANY_HINT.items():
            if key in low:
                brand = cn
                break
        if brand:
            app, source = f"{brand} 的 {name or '程序'}", "company"
    return {"app": app, "product": prod, "company": comp,
            "version": vinfo.get("version", ""), "source": source or "none"}
