@echo off
chcp 65001 >nul
setlocal enableextensions
title 智能合约漏洞审计系统 - 一键启动
cd /d "%~dp0"

set "MYSQLD=D:\shujuku\mysql-8.0.46-winx64\bin\mysqld.exe"
set "MYSQL_INI=D:\shujuku\mysql-8.0.46-winx64\my.ini"
set "FLAG=.mysql_started_by_launcher"

echo ============================================================
echo    智能合约漏洞审计系统 - 一键启动
echo ============================================================
echo.

REM ---------- 1. MySQL 数据库 ----------
netstat -ano | findstr ":3306" | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [1/3] MySQL 已在运行（端口 3306）
    goto mysql_ok
)
if not exist "%MYSQLD%" (
    echo [1/3] 未找到 mysqld.exe：%MYSQLD%
    echo       请先手动启动 MySQL，或修改本脚本中的 MYSQLD 路径。
    goto mysql_ok
)

echo [1/3] 启动 MySQL 数据库...
start "MySQL" /min "%MYSQLD%" --defaults-file="%MYSQL_INI%"
echo started>"%FLAG%"

set /a TRY=0
:wait_mysql
ping -n 2 127.0.0.1 >nul
netstat -ano | findstr ":3306" | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 goto mysql_ok
set /a TRY+=1
if %TRY% GEQ 30 (
    echo       MySQL 启动超时，请检查 %MYSQL_INI% 配置。
    goto mysql_ok
)
goto wait_mysql

:mysql_ok
echo.

REM ---------- 2. Flask 后端 ----------
netstat -ano | findstr ":5000" | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [2/3] 5000 端口已占用，后端可能已在运行
    goto flask_ok
)

echo [2/3] 启动 Flask 后端（新窗口）...
start "智能合约漏洞审计系统 - 后端" cmd /k python app.py

set /a TRY=0
:wait_flask
ping -n 2 127.0.0.1 >nul
netstat -ano | findstr ":5000" | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 goto flask_ok
set /a TRY+=1
if %TRY% GEQ 20 (
    echo       后端启动超时，请查看后端窗口中输出的报错信息。
    goto flask_ok
)
goto wait_flask

:flask_ok
echo.

REM ---------- 3. 打开浏览器 ----------
echo [3/3] 打开浏览器：http://127.0.0.1:5000
start "" http://127.0.0.1:5000

echo.
echo ============================================================
echo    启动完成
echo    默认管理员：admin / 123456
echo    关闭服务：运行 stop.bat
echo ============================================================
echo.
pause
