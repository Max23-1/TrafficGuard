@echo off
chcp 65001 >nul
setlocal
title 流量哨兵
cd /d "%~dp0"

set "PYCMD="
where py >nul 2>nul && set "PYCMD=py -3"
if not defined PYCMD (
    where python >nul 2>nul && set "PYCMD=python"
)
if not defined PYCMD (
    if exist "D:\python\pythonw.exe" set "PYCMD=D:\python\pythonw.exe"
)
if not defined PYCMD (
    echo [错误] 未检测到 Python 3，请先安装 Python 3.10+ 并勾选 "Add to PATH"。
    pause
    exit /b 1
)

echo 正在启动流量哨兵（会请求管理员权限，用于写入防火墙规则）……
%PYCMD% "%~dp0run.py"
if errorlevel 1 (
    echo.
    echo 启动未成功，请查看 data\logs\traffic_guard.log
    pause
)
endlocal
