@echo off
schtasks /End /TN "CiscoAnyConnectMonitorServer" >nul 2>&1
schtasks /Delete /F /TN "CiscoAnyConnectMonitorServer"
pause
