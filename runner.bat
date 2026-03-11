@echo off
setlocal

:: ── Elevation check ──────────────────────────────────────────────────────────
NET SESSION >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Administrator privileges required. Re-launching as Administrator...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c \"%~f0\"' -Verb RunAs"
    exit /b
)

echo  [+] Running as Administrator.

:: ── Launch the PowerShell security script ────────────────────────────────────
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0win_more_secure.ps1"
if errorlevel 1 (
    echo.
    echo  [-] The script exited with an error.
    echo  [!] Ensure you are running Windows 10 or Windows 11 with PowerShell 5.1+.
    pause
)

endlocal
