# 第三方组件与数据声明

本项目（流量哨兵 TrafficGuard）以 MIT 许可证发布，但包含或依赖以下第三方组件与数据，
它们各自适用不同的许可条款。

## 运行时依赖

| 组件 | 版本 | 许可证 | 用途 | 说明 |
| --- | --- | --- | --- | --- |
| [pystray](https://github.com/moses-palmer/pystray) | 0.19.x | LGPL-3.0 | 系统托盘图标 | 以**未修改的独立库**形式使用；本项目完整公开源码与构建脚本，满足 LGPL 对「可替换/可重链接」的要求。若你修改并重新分发 pystray 本身，需遵循 LGPL-3.0。 |
| [Pillow](https://python-pillow.org/) | 12/13.x | HPND（PIL 许可证） | 生成托盘图标 | 宽松许可证，允许分发。 |
| Tcl/Tk（tkinter） | 随 Python | BSD 类 | 弹窗界面 | Python 标准库自带。 |
| Python | 3.10+ | PSF License | 运行时 | 打包版已内嵌解释器。 |

## 构建期依赖（不随程序分发）

| 组件 | 许可证 | 说明 |
| --- | --- | --- |
| [PyInstaller](https://pyinstaller.org/) | GPL-2.0-or-later，附「打包非自由程序」例外条款 | 仅用于生成 exe；其例外条款明确允许打包并分发闭源/其他许可证的程序。 |

## 数据

| 数据 | 许可证 | 说明 |
| --- | --- | --- |
| MaxMind GeoLite2-Country | [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) | **本仓库不包含该数据库**。程序在用户本机首次运行时下载；使用者需自行遵守 MaxMind 的许可条款（通常需要注册账号，且不得再分发数据库）。可通过 `MAXMIND_LICENSE_KEY` 使用官方直链。 |
| DB-IP Lite（可选替代） | CC BY 4.0 | 使用者可自行替换为 DB-IP Lite，需保留其署名。 |

## 图标

项目图标由本项目通过 Pillow 程序化生成（`build.py` 中的 `make_icon()`），不含第三方素材。
