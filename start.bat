@echo off
setlocal
cd /d "%~dp0"

echo === Privacy Messenger: Start ===

where python >nul 2>nul
if errorlevel 1 (
    echo [FEHLER] Python wurde nicht gefunden. Bitte Python installieren und zum PATH hinzufuegen.
    pause
    exit /b 1
)

echo [1/2] Pruefe Python-Abhaengigkeiten...
python -c "import nacl, fastapi, uvicorn, pydantic, websockets" >nul 2>nul
if errorlevel 1 (
    echo Abhaengigkeiten fehlen, installiere aus requirements.txt...
    python -m pip install -r requirements.txt
)

rem Wichtig: Das Backend wird NICHT hier separat gestartet.
rem Electron (main.js) startet das Python-Backend selbst und uebergibt ihm
rem automatisch ein passendes API-Token. Ein zusaetzlicher, hier gestarteter
rem Backend-Prozess wuerde ein ANDERES Token verwenden und alle Anfragen des
rem Frontends (inkl. Tresor-Entsperren) mit 403 Access Denied fehlschlagen lassen.

echo [2/2] Starte Privacy Messenger (Electron startet das Backend automatisch)...
if not exist "node_modules" (
    echo node_modules fehlt, fuehre npm install aus...
    call npm install
)
call npm start

endlocal
