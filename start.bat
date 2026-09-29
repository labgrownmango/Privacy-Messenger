@echo off
setlocal
cd /d "%~dp0"

echo === Privacy Messenger: Backend + Frontend Start ===

where python >nul 2>nul
if errorlevel 1 (
    echo [FEHLER] Python wurde nicht gefunden. Bitte Python installieren und zum PATH hinzufuegen.
    pause
    exit /b 1
)

echo [1/2] Starte Backend (FastAPI)...
start "Privacy Messenger Backend" cmd /k "cd /d "%~dp0backend" && python server.py"

echo Warte auf Backend-Start...
timeout /t 3 /nobreak >nul

echo [2/2] Starte Electron-Frontend...
if not exist "node_modules" (
    echo node_modules fehlt, fuehre npm install aus...
    call npm install
)
call npm start

endlocal
