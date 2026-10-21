"""构建发布包：生成图标、版本信息，并调用 PyInstaller 打包。

用法：
    python build.py            # 单文件 exe（dist/TrafficGuard.exe）
    python build.py --onedir   # 文件夹版（dist/TrafficGuard/）
    python build.py --all      # 两种都构建
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"
DIST = ROOT / "dist"
VERSION = "2.1.0"
NAME = "TrafficGuard"


def make_icon() -> Path:
    from PIL import Image, ImageDraw

    BUILD.mkdir(exist_ok=True)
    target = BUILD / "icon.ico"
    size = 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # 圆角底板 + 渐变（用多层同心圆角矩形近似）
    for i in range(24):
        t = i / 23
        color = (int(28 + 34 * t), int(80 + 62 * t), int(190 + 57 * t), 255)
        inset = 10 + i
        d.rounded_rectangle((inset, inset, size - inset, size - inset),
                            radius=48 - i, fill=color)
    # 白色雷达环
    d.ellipse((56, 56, 200, 200), outline=(255, 255, 255, 235), width=10)
    d.ellipse((92, 92, 164, 164), outline=(255, 255, 255, 150), width=6)
    d.ellipse((118, 118, 138, 138), fill=(255, 255, 255, 255))
    # 右上角警示点
    d.ellipse((186, 26, 226, 66), fill=(229, 72, 77, 255), outline=(255, 255, 255, 255), width=5)

    sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    img.save(target, format="ICO", sizes=sizes)
    return target


def write_version_file() -> Path:
    BUILD.mkdir(exist_ok=True)
    target = BUILD / "version_info.txt"
    target.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({VERSION.replace('.', ', ')}, 0),
    prodvers=({VERSION.replace('.', ', ')}, 0),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('080404b0', [
        StringStruct('CompanyName', 'TrafficGuard'),
        StringStruct('FileDescription', 'TrafficGuard - local traffic monitor'),
        StringStruct('FileVersion', '{VERSION}.0'),
        StringStruct('InternalName', 'TrafficGuard'),
        StringStruct('OriginalFilename', 'TrafficGuard.exe'),
        StringStruct('ProductName', 'TrafficGuard'),
        StringStruct('ProductVersion', '{VERSION}.0'),
        StringStruct('LegalCopyright', 'Local only. No data leaves this machine.')
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [2052, 1200])])
  ]
)
""", encoding="utf-8")
    return target


def run_pyinstaller(onefile: bool) -> int:
    icon = make_icon()
    version_file = write_version_file()
    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", NAME,
        "--icon", str(icon),
        "--version-file", str(version_file),
        "--add-data", f"{ROOT / 'web'};web",
    ]
    # IP 库属于 MaxMind 授权数据，公开仓库不自带；存在时才打包进 exe
    geoip = ROOT / "data" / "GeoLite2-Country.mmdb"
    if geoip.exists():
        args += ["--add-data", f"{geoip};data"]
    else:
        print("[提示] 未找到 data/GeoLite2-Country.mmdb，exe 将在首次运行时自动下载")
    args += [
        "--hidden-import", "pystray._win32",
        "--hidden-import", "PIL._tkinter_finder",
        "--exclude-module", "numpy",
        "--exclude-module", "pandas",
        "--exclude-module", "matplotlib",
        "--exclude-module", "scipy",
        "--exclude-module", "pytest",
        "--uac-admin",
        "--windowed",
        "--onefile" if onefile else "--onedir",
        "--distpath", str(DIST / ("onefile" if onefile else "onedir")),
        str(ROOT / "run.py"),
    ]
    print("==>", " ".join(args[2:]))
    return subprocess.call(args, cwd=str(ROOT))


def main() -> int:
    argv = sys.argv[1:]
    onefile = "--onefile" in argv
    onedir = "--onedir" in argv
    both = "--all" in argv or not (onefile or onedir)
    rc = 0
    if both or onefile:
        rc |= run_pyinstaller(True)
    if both or onedir:
        rc |= run_pyinstaller(False)
    return rc


if __name__ == "__main__":
    sys.exit(main())

