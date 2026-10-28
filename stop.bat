@echo off
chcp 65001 >nul
setlocal
title 智能合约漏洞审计系统 - 停止服务
cd /d "%~dp0"

set "FLAG=.mysql_started_by_launcher"

echo ============================================================
echo    智能合约漏洞审计系统 - 停止服务
echo ============================================================
echo.

echo [1/2] 停止 Flask 后端...
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -like '*app.py*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }" 2>nul
echo       完成

echo [2/2] 处理 MySQL...
if exist "%FLAG%" (
    taskkill /F /IM mysqld.exe >nul 2>&1
    del "%FLAG%" >nul 2>&1
    echo       MySQL 已停止（由一键启动脚本拉起）
) else (
    echo       MySQL 由外部启动，本脚本不停止它；
    echo       如需停止请手动关闭 MySQL 服务或进程。
)

echo.
echo 服务已停止。
pause
