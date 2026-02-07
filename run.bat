@echo off
REM Activate virtual environment and run Flask app

echo Activating virtual environment...
call .venv\Scripts\activate.bat

echo Installing dependencies...
pip install -r requirements.txt

echo Starting Flask application...
python app.py

pause
