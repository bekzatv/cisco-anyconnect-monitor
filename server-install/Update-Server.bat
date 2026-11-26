@echo off
rem Updates the monitor to the latest release from GitHub. Run as Administrator.
rem Examples: Update-Server.bat -CheckOnly    Update-Server.bat -EnableAuto
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Update-Server.ps1" %*
pause
