@echo off
setlocal
cd /d "%~dp0"

echo.
echo [START] discord-pxe-sharded
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\setup-pxe.ps1" -NoSerial
set "rc=%errorlevel%"
if not "%rc%"=="0" goto :fail

echo.
echo [READY] PXE server setup finished
echo [READY] boot the target with Legacy Network/PXE
echo [SERIAL] target broadcasts diagnostics to COM1/COM2/COM3/COM4 at 115200 8N1
echo.
echo press any key to close this window
pause >nul
exit /b 0

:fail
echo.
echo [ERROR] run failed with exit code %rc%
echo.
echo press any key to close this window
pause >nul
exit /b %rc%
