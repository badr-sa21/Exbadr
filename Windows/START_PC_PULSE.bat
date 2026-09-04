@echo off
setlocal
cd /d "%~dp0"
title PC Pulse v0.1

echo ============================================================
echo                     PC Pulse v0.1
echo ============================================================
echo.

where py >nul 2>nul
if %errorlevel%==0 (
    set PY=py
    goto :havepython
)

where python >nul 2>nul
if %errorlevel%==0 (
    set PY=python
    goto :havepython
)

echo [ERROR] Python was not found.
echo Install Python 3.11+ and enable "Add Python to PATH".
pause
exit /b 1

:havepython
echo Installing/checking packages...
%PY% -m pip install --disable-pip-version-check flask psutil qrcode[pil]
if errorlevel 1 (
    echo.
    echo [ERROR] Package installation failed.
    pause
    exit /b 1
)

echo.
%PY% pc_pulse_server.py
echo.
pause
