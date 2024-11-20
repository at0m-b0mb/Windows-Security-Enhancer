@echo off
:: Check if the script is running as Administrator
NET SESSION >nul 2>&1
if %errorlevel% == 0 (
    echo Running as Administrator, proceeding...
) else (
    echo This script requires Administrator privileges. Restarting as Administrator...
    powershell -Command "Start-Process cmd -ArgumentList '/c %~s0' -Verb runAs"
    exit
)

:: Run the PowerShell script from the same directory as this .bat file
powershell -ExecutionPolicy Bypass -File "%~dp0win_more_secure.ps1"
