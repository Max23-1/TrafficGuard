@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "PYW=%LocalAppData%\Programs\Python\Python312\pythonw.exe"
if not exist "%PYW%" set "PYW=D:\python\pythonw.exe"
if not exist "%PYW%" (
    for /f "delims=" %%i in ('where pythonw') do set "PYW=%%i"
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
 "$a=New-ScheduledTaskAction -Execute '%PYW%' -Argument '\"%CD%\run.py\" --elevated' -WorkingDirectory '%CD%';" ^
 "$t=New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME;" ^
 "$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0;" ^
 "$p=New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest;" ^
 "Register-ScheduledTask -TaskName 'TrafficGuard' -Action $a -Trigger $t -Settings $s -Principal $p -Force | Out-Null"

echo 已设置开机自启：计划任务 TrafficGuard（最高权限，登录后自动运行）。
pause
endlocal
