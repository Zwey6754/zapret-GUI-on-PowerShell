@echo off
:: Zapret GUI Launcher
:: This file launches the PowerShell GUI interface

echo Starting Zapret GUI Manager...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0zapret-gui.ps1"

if errorlevel 1 (
    echo.
    echo Failed to start GUI. Press any key to exit...
    pause >nul
)