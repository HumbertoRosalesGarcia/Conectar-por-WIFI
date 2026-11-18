@echo off
title Administrador Visual de Dispositivos Wi-Fi ADB
set "PYTHONW_EXE=C:\Users\Administrador\AppData\Local\Programs\Python\Python314\pythonw.exe"
set "APP_SCRIPT=%~dp0multi_adb_wifi.py"

if exist "%PYTHONW_EXE%" (
    start "" "%PYTHONW_EXE%" "%APP_SCRIPT%"
) else (
    start "" pythonw "%APP_SCRIPT%"
)
exit /b 0
