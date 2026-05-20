@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: =========================================================================
::  Windows Security Enhancer  -  launcher
::  Offers a GUI / CLI choice, self-elevates via UAC, then hands off to
::  the appropriate PowerShell script.
::  Nothing needs to be installed - WPF is built in to every Windows release.
:: =========================================================================

set "SCRIPT_DIR=%~dp0"
set "ENGINE=%SCRIPT_DIR%win_more_secure.ps1"
set "GUI=%SCRIPT_DIR%win_more_secure_gui.ps1"

if not exist "%ENGINE%" (
    echo  [-] Cannot find win_more_secure.ps1 next to runner.bat.
    echo      Expected location: "%ENGINE%"
    pause
    exit /b 1
)

:: --- elevation check ----------------------------------------------------
fltmc >nul 2>&1
if %errorlevel% NEQ 0 (
    echo  [!] Administrator privileges required. Re-launching as Administrator...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    exit /b
)

:: --- argument routing ---------------------------------------------------
set "MODE=%~1"
if /I "%MODE%"=="--gui"     goto launch_gui
if /I "%MODE%"=="-gui"      goto launch_gui
if /I "%MODE%"=="gui"       goto launch_gui
if /I "%MODE%"=="--cli"     goto launch_cli
if /I "%MODE%"=="-cli"      goto launch_cli
if /I "%MODE%"=="cli"       goto launch_cli
if /I "%MODE%"=="--apply"   ( shift & goto launch_apply )
if /I "%MODE%"=="-apply"    ( shift & goto launch_apply )
if /I "%MODE%"=="apply"     ( shift & goto launch_apply )
if /I "%MODE%"=="--quick"   ( shift & goto launch_quick )
if /I "%MODE%"=="-quick"    ( shift & goto launch_quick )
if /I "%MODE%"=="quick"     ( shift & goto launch_quick )
if /I "%MODE%"=="--status"  ( shift & goto launch_status )
if /I "%MODE%"=="-status"   ( shift & goto launch_status )
if /I "%MODE%"=="status"    ( shift & goto launch_status )
if /I "%MODE%"=="--report"  ( shift & goto launch_report )
if /I "%MODE%"=="-report"   ( shift & goto launch_report )
if /I "%MODE%"=="report"    ( shift & goto launch_report )
if /I "%MODE%"=="--help"    goto show_help
if /I "%MODE%"=="-help"     goto show_help
if /I "%MODE%"=="-?"        goto show_help
if /I "%MODE%"=="/?"        goto show_help

:: --- interactive selector ---------------------------------------------
cls
echo.
echo  ============================================================
echo     W I N D O W S   S E C U R I T Y   E N H A N C E R   v5.1
echo  ============================================================
echo.
echo   How would you like to run it?
echo.
echo     [1]  Graphical interface  (recommended)
echo     [2]  Classic terminal menu
echo     [3]  Quick Win preset  (run safe defaults right now)
echo     [4]  Show security status only
echo     [5]  Export HTML security report
echo     [6]  Help / command-line usage
echo     [Q]  Quit
echo.
set "PICK="
set /p "PICK=  Enter choice: "
if /I "%PICK%"=="1" goto launch_gui
if /I "%PICK%"=="2" goto launch_cli
if /I "%PICK%"=="3" goto launch_quick
if /I "%PICK%"=="4" goto launch_status
if /I "%PICK%"=="5" goto launch_report
if /I "%PICK%"=="6" goto show_help
if /I "%PICK%"=="Q" exit /b 0
echo.
echo   Invalid selection.
timeout /t 2 >nul
goto :EOF

:: --- launchers ----------------------------------------------------------
:launch_gui
if not exist "%GUI%" (
    echo  [-] GUI script missing: "%GUI%"
    echo      Falling back to the CLI menu.
    pause
    goto launch_cli
)
echo  [+] Launching graphical interface...
powershell -NoProfile -ExecutionPolicy Bypass -File "%GUI%"
exit /b %errorlevel%

:launch_cli
echo  [+] Launching terminal menu...
powershell -NoProfile -ExecutionPolicy Bypass -File "%ENGINE%"
set "PS_EXIT=%errorlevel%"
if %PS_EXIT% NEQ 0 (
    echo.
    echo  [-] The script exited with code %PS_EXIT%.
    pause
)
exit /b %PS_EXIT%

:launch_apply
echo  [+] Applying ALL hardening (non-interactive)...
powershell -NoProfile -ExecutionPolicy Bypass -File "%ENGINE%" -Apply
pause
exit /b %errorlevel%

:launch_quick
echo  [+] Applying Quick Win preset (non-interactive)...
powershell -NoProfile -ExecutionPolicy Bypass -File "%ENGINE%" -QuickWin
pause
exit /b %errorlevel%

:launch_status
powershell -NoProfile -ExecutionPolicy Bypass -File "%ENGINE%" -Status
pause
exit /b %errorlevel%

:launch_report
powershell -NoProfile -ExecutionPolicy Bypass -File "%ENGINE%" -Report
pause
exit /b %errorlevel%

:show_help
cls
echo.
echo  Windows Security Enhancer - launcher usage
echo  ------------------------------------------
echo.
echo    runner.bat                  Interactive launcher (GUI / CLI / preset)
echo    runner.bat gui              Launch the graphical interface
echo    runner.bat cli              Launch the classic menu in PowerShell
echo    runner.bat quick            Apply the Quick Win preset, then exit
echo    runner.bat apply            Apply ALL hardening, then exit
echo    runner.bat status           Print the security status report
echo    runner.bat report           Export the HTML security report
echo    runner.bat help             Show this help text
echo.
echo  Logs and backups land in:
echo     %%ProgramData%%\WSE\logs
echo     %%ProgramData%%\WSE\backups
echo.
pause
goto :EOF
