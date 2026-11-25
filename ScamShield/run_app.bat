@echo off
REM Double-click this file to start ScamShield. The website opens in your browser.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo First-time setup, please wait...
  python -m venv .venv
  .venv\Scripts\python.exe -m pip install -r requirements.txt
)
if not exist "data\model\scam_model.joblib" .venv\Scripts\python.exe scripts\train.py
echo.
echo  ScamShield is running at  http://localhost:8000
echo  API documentation at      http://localhost:8000/docs
echo  Close this window to stop.
echo.
start "" http://localhost:8000
.venv\Scripts\python.exe -m uvicorn web.server:app --port 8000
pause
