@echo off
chcp 65001 >nul 2>&1
title DEVOPS_driver — Setup & Launch
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File setup.ps1
if errorlevel 1 (
    echo.
    echo [错误] 脚本执行失败。
    pause
)
