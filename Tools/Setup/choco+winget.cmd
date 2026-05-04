@echo off
setlocal EnableExtensions
title CHOCOLATEY + WINGET - INSTALLER

echo.
echo ============================================================
echo  CHOCOLATEY + WINGET - INSTALLER
echo ============================================================
echo.

REM ============================================================
REM 1. CHECK FOR ADMINISTRATOR PRIVILEGES
REM ============================================================

echo [1/4] Checking administrator privileges...

fltmc >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Administrator privileges are required.
    echo [INFO] Right-click the CMD file and select Run as administrator.
    goto END
)

echo [OK] Running as administrator.
echo.

REM ============================================================
REM 2. CHECK FOR CHOCOLATEY
REM ============================================================

echo [2/4] Checking Chocolatey installation...

where choco.exe >nul 2>&1
if not errorlevel 1 (
    echo [OK] Chocolatey is already installed.
    goto CHECK_WINGET
)

if exist "%ProgramData%\chocolatey\bin\choco.exe" (
    set "PATH=%ProgramData%\chocolatey\bin;%PATH%"
    echo [OK] Chocolatey is already installed.
    goto CHECK_WINGET
)

echo [INFO] Chocolatey not found. Installing...
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; try { Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')); exit 0 } catch { Write-Host ('[ERROR] ' + $_.Exception.Message); exit 1 }"

if errorlevel 1 (
    echo.
    echo [ERROR] Chocolatey installation failed.
    echo [INFO] Check your internet connection or install it manually.
    goto CHECK_WINGET
)

if exist "%ProgramData%\chocolatey\bin" (
    set "PATH=%ProgramData%\chocolatey\bin;%PATH%"
)

where choco.exe >nul 2>&1
if errorlevel 1 (
    if not exist "%ProgramData%\chocolatey\bin\choco.exe" (
        echo [ERROR] Chocolatey installation could not be verified.
        goto CHECK_WINGET
    )
)

echo [OK] Chocolatey installed successfully.
echo.

REM ============================================================
REM 3. CHECK FOR WINGET
REM ============================================================

:CHECK_WINGET

echo [3/4] Checking WinGet installation...

where winget.exe >nul 2>&1
if not errorlevel 1 (
    echo [OK] WinGet is already installed.
    goto END
)

echo [INFO] WinGet not found. Attempting installation...
echo.

set "WINGET_INSTALLER=%TEMP%\winget-install-%RANDOM%.ps1"

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; try { Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/asheroto/winget-install/master/winget-install.ps1' -OutFile $env:WINGET_INSTALLER -UseBasicParsing -ErrorAction Stop; exit 0 } catch { Write-Host ('[ERROR] ' + $_.Exception.Message); exit 1 }"

if errorlevel 1 (
    echo [ERROR] Failed to download the WinGet installer.
    goto WINGET_CLEANUP
)

if not exist "%WINGET_INSTALLER%" (
    echo [ERROR] WinGet installer file was not created.
    goto WINGET_CLEANUP
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%WINGET_INSTALLER%"

if errorlevel 1 (
    echo [ERROR] WinGet installation reported a failure.
    goto WINGET_CLEANUP
)

where winget.exe >nul 2>&1
if errorlevel 1 (
    echo [INFO] WinGet may require a new terminal session to become available.
    echo [INFO] Check its availability after installation.
    goto WINGET_CLEANUP
)

echo [OK] WinGet installed successfully.
echo.

:WINGET_CLEANUP

if exist "%WINGET_INSTALLER%" del /f /q "%WINGET_INSTALLER%" >nul 2>&1

REM ============================================================
REM 4. AUTOMATIC CLOSE
REM ============================================================

:END

echo.
echo ============================================================
echo  PROCESS FINISHED
echo ============================================================
echo.
echo [INFO] Closing automatically in 7 seconds...

timeout /t 7 /nobreak >nul

endlocal
exit
