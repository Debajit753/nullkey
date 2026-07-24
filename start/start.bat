@echo off
REM ===========================================================================
REM  Nullkey launcher - Windows
REM  Double-click to open a terminal, set up the venv on first run, and start
REM  Nullkey. No manual cd / activate needed.
REM ===========================================================================
title Nullkey
cd /d "%~dp0.."

REM --- find Python ---
set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY (
  where py >nul 2>&1 && set "PY=py -3"
)
if not defined PY (
  echo Python 3.9+ was not found. Install it from https://www.python.org/downloads/
  echo ^(tick "Add Python to PATH" during install^), then run this again.
  pause
  exit /b 1
)

REM --- first run: create venv + install deps ---
if not exist ".venv\Scripts\activate.bat" (
  echo First run - setting up the virtual environment ^(one time, ~1 min^)...
  %PY% -m venv .venv
  if errorlevel 1 ( echo Could not create the virtualenv. & pause & exit /b 1 )
  call ".venv\Scripts\activate.bat"
  python -m pip install --upgrade pip
  pip install -r requirements.txt
  if errorlevel 1 ( echo Dependency install failed. & pause & exit /b 1 )
) else (
  call ".venv\Scripts\activate.bat"
)

echo.
echo Starting Nullkey...  ^(press Ctrl+C to quit^)
echo Tip: for a local no-Tor test:  start.bat --local --data-dir .\peerA
echo.
python nullkey.py %*

echo.
echo Nullkey has exited.
pause
