@echo off
setlocal
cd /d "%~dp0"
rem Registers a Task Scheduler task that starts the collector at user logon.
rem It runs as the current user: the router password is DPAPI-encrypted for this user only.
set TASK=CiscoAnyConnectMonitorServer
if exist "%~dp0dist\CiscoAnyConnectServer.exe" (
    set "CMD=\"%~dp0dist\CiscoAnyConnectServer.exe\""
) else if exist "%LocalAppData%\Programs\Python\Python313\pythonw.exe" (
    set "CMD=\"%LocalAppData%\Programs\Python\Python313\pythonw.exe\" \"%~dp0server.py\""
) else (
    echo pythonw.exe not found. Build the EXE first: Build-Exe.bat
    pause
    exit /b 1
)
schtasks /Create /F /TN "%TASK%" /SC ONLOGON /RL LIMITED /TR "%CMD%"
if errorlevel 1 (
    echo Failed to create the task.
) else (
    echo Autostart enabled: task "%TASK%". Remove it with Remove-Autostart.bat
    schtasks /Run /TN "%TASK%" >nul
)
pause
