@echo off
setlocal EnableExtensions

:: =========================================================================
::  Windows Security Enhancer — launcher
::  - Verifies the PowerShell script exists next to this batch file
::  - Self-elevates via UAC if not already running as Administrator
::  - Launches the menu-driven PowerShell hardening toolkit
:: =========================================================================

set "SCRIPT_DIR=%~dp0"
set "PS1_PATH=%SCRIPT_DIR%win_more_secure.ps1"

if not exist "%PS1_PATH%" (
    echo  [-] Cannot find win_more_secure.ps1 next to runner.bat.
    echo      Expected location: "%PS1_PATH%"
    pause
    exit /b 1
)

:: -- elevation check ------------------------------------------------------
fltmc >nul 2>&1
if %errorlevel% NEQ 0 (
    echo  [!] Administrator privileges required. Re-launching as Administrator...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath '%~f0' -Verb RunAs"
    if errorlevel 1 (
        echo  [-] Elevation was cancelled or failed.
        pause
    )
    exit /b
)

echo  [+] Running as Administrator.
echo  [+] Launching Windows Security Enhancer ...
echo.

:: -- launch ---------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1_PATH%"
set "PS_EXIT=%errorlevel%"

if %PS_EXIT% NEQ 0 (
    echo.
    echo  [-] The script exited with code %PS_EXIT%.
    echo  [!] Ensure you are running Windows 10 / 11 / Server with PowerShell 5.1+.
    pause
)

endlocal
