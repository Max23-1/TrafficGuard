@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
set "PYCMD="
where py >nul 2>nul && set "PYCMD=py -3"
if not defined PYCMD (
    where python >nul 2>nul && set "PYCMD=python"
)
if not defined PYCMD set "PYCMD=D:\python\python.exe"
%PYCMD% "%~dp0stop.py"
timeout /t 3 >nul
endlocal
