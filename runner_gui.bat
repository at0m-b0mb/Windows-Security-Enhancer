@echo off
setlocal EnableExtensions

:: =========================================================================
::  Windows Security Enhancer  -  GUI launcher
::  - Verifies the GUI script exists next to this batch file
::  - Self-elevates via UAC if not already running as Administrator
::  - Launches the WPF graphical interface (no installation required)
:: =========================================================================

set "SCRIPT_DIR=%~dp0"
set "GUI=%SCRIPT_DIR%win_more_secure_gui.ps1"
set "ENGINE=%SCRIPT_DIR%win_more_secure.ps1"

if not exist "%GUI%" (
    echo  [-] Cannot find win_more_secure_gui.ps1 next to runner_gui.bat.
    echo      Expected location: "%GUI%"
    pause
    exit /b 1
)
if not exist "%ENGINE%" (
    echo  [-] Cannot find win_more_secure.ps1 next to runner_gui.bat.
    echo      The GUI depends on the engine script.
    pause
    exit /b 1
)

fltmc >nul 2>&1
if %errorlevel% NEQ 0 (
    echo  [!] Administrator privileges required. Re-launching as Administrator...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo  [+] Launching Windows Security Enhancer GUI ...
powershell -NoProfile -ExecutionPolicy Bypass -File "%GUI%"
set "PS_EXIT=%errorlevel%"
if %PS_EXIT% NEQ 0 (
    echo.
    echo  [-] The GUI exited with code %PS_EXIT%.
    pause
)
endlocal
