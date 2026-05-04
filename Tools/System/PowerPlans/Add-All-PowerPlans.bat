@echo off
setlocal enabledelayedexpansion

REM Check for Administrative Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo =======================================================
    echo ERROR: Administrative privileges required!
    echo Please right-click this BAT file and select "Run as administrator".
    echo =======================================================
    pause
    exit /b
)

echo Importing power plan (.pow) files...
echo.

REM Folder where the BAT script is located
set "folder=%~dp0"

REM Search and import all .pow files in the directory
set count=0
for %%f in ("%folder%*.pow") do (
    set /a count+=1
    echo [!count!] Importing %%~nxf...
    powercfg -import "%%f"
)

if %count%==0 (
    echo No .pow files found in this directory!
    pause
    exit /b
)

echo.
echo   [!] System exiting in 5 seconds...
timeout /t 5 /nobreak >nul
exit
