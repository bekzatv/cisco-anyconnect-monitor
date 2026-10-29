@echo off
setlocal
cd /d "%~dp0"
rem Saves the database, router SSH keys and settings (without passwords) into a zip on the Desktop
rem for Install-Server.ps1 on the Windows Server. Safe to run while the monitor is working.
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmm"') do set STAMP=%%i
set "OUT=%USERPROFILE%\Desktop\vpnmon-transfer-%STAMP%.zip"
if exist "%~dp0dist\CiscoAnyConnectServer.exe" (
    "%~dp0dist\CiscoAnyConnectServer.exe" --export-bundle "%OUT%"
) else (
    rem The working data lives next to the EXE in dist\, not in the source folder.
    "%LocalAppData%\Programs\Python\Python313\python.exe" "%~dp0server.py" --data-dir "%~dp0dist" --export-bundle "%OUT%"
)
