@echo off
setlocal
cd /d "%~dp0"
rem Starts the background collector + web panel without a console window.
rem Panel: http://127.0.0.1:8765/
if exist "%~dp0dist\CiscoAnyConnectServer.exe" (
    start "" "%~dp0dist\CiscoAnyConnectServer.exe" --open
) else if exist "%LocalAppData%\Programs\Python\Python313\pythonw.exe" (
    start "" "%LocalAppData%\Programs\Python\Python313\pythonw.exe" "%~dp0server.py" --open
) else (
    start "" pythonw "%~dp0server.py" --open
)
