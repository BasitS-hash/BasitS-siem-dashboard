@echo off
REM SIEM Dashboard Startup Script for Windows

echo Starting SIEM Dashboard...

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install/update dependencies
echo Installing dependencies...
pip install -q -r requirements.txt

REM Generate sample data if logs directory is empty
if not exist "logs\system.log" (
    echo Generating sample log data...
    python generate_sample_data.py
)

REM Initialize database
echo Initializing database...
python -c "from app import server, db; app_context = server.app_context(); app_context.push(); db.create_all(); app_context.pop()"

REM Start log ingestion service in background
echo Starting log ingestion service...
start /B python log_ingestion.py > ingestion.log 2>&1

REM Wait a moment for ingestion to start
timeout /t 2 /nobreak > nul

REM Start dashboard
echo Starting dashboard...
echo Dashboard will be available at http://localhost:8050
echo.
echo Press Ctrl+C to stop all services
echo.

python app.py

REM Cleanup on exit
taskkill /F /IM python.exe /FI "WINDOWTITLE eq log_ingestion*" > nul 2>&1
