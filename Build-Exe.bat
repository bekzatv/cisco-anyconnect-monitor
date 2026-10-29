@echo off
setlocal
cd /d "%~dp0"
set PYTHON_EXE=python
if exist "%LocalAppData%\Programs\Python\Python313\python.exe" (
    set "PYTHON_EXE=%LocalAppData%\Programs\Python\Python313\python.exe"
)
"%PYTHON_EXE%" -m pip install -r requirements.txt
"%PYTHON_EXE%" -m unittest discover -s tests -p "test_*.py" || (echo Tests failed & pause & exit /b 1)

rem Desktop app (Tkinter)
"%PYTHON_EXE%" -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name "CiscoAnyConnectMonitor" ^
    --icon "assets\CiscoAnyConnectMonitor.ico" ^
    --add-data "assets\CiscoAnyConnectMonitor.ico;assets" ^
    --add-data "assets\CiscoAnyConnectMonitor.png;assets" ^
    app.py

rem Background collector + web panel
"%PYTHON_EXE%" -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name "CiscoAnyConnectServer" ^
    --icon "assets\CiscoAnyConnectMonitor.ico" ^
    --add-data "vpnmon\web;vpnmon\web" ^
    server.py
rem Everything to copy to the Windows Server in one folder
if not exist "dist\server-package" mkdir "dist\server-package"
copy /y "dist\CiscoAnyConnectServer.exe" "dist\server-package\" >nul
copy /y "server-install\*.*" "dist\server-package\" >nul
echo.
echo Build complete: dist\CiscoAnyConnectMonitor.exe, dist\CiscoAnyConnectServer.exe
echo Server package: dist\server-package\
pause
