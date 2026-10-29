@echo off
rem Runs Install-Server.ps1 bypassing the script execution policy. Run as Administrator.
rem Example: Install-Server.bat -Bundle C:\Temp\vpnmon-transfer.zip
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-Server.ps1" %*
pause
