@echo off
chcp 65001 >nul
setlocal
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
schtasks /delete /tn "TrafficGuard" /f
echo 已取消开机自启。
pause
endlocal
