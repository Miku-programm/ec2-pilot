@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  py -3 -m venv .venv
  if errorlevel 1 goto failure
)
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto failure
echo Open http://127.0.0.1:8080 in your browser.
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 1
goto end
:failure
echo Install Python 3.11 or newer, then run this file again.
pause
:end
