@echo off
chcp 65001 >nul
title 智能合约漏洞审计系统 - 后端服务
cd /d %~dp0
echo [启动] Flask 后端 + 前端页面  http://127.0.0.1:5000
echo [说明] 需先启动 MySQL80 服务（账号 root/123456）
python app.py
pause
