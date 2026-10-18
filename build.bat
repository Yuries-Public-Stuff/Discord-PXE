@echo off
setlocal
cd /d "%~dp0"

echo.
echo [BUILD] legacy PXE image
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\build.ps1"
set "rc=%errorlevel%"
if not "%rc%"=="0" goto :fail

echo.
echo [READY] build finished
echo [READY] build\stage1.pxe
echo [READY] build\runtime.bin
echo.
echo press any key to close
pause >nul
exit /b 0

:fail
echo.
echo [ERROR] build failed with exit code %rc%
echo.
echo press any key to close
pause >nul
exit /b %rc%
