```bat
@echo off
setlocal EnableExtensions
title Remove Windows AI - Configuration

echo.
echo ========================================================
echo              REMOVE WINDOWS AI - MODULE
echo ========================================================
echo.

:: ------------------------------------------------
:: TIMED CONFIRMATION - DEFAULT YES AFTER 5 SECONDS
:: ------------------------------------------------

echo Do you want to remove Windows AI features?
echo Press Y to confirm or N to cancel.
echo Default: YES - Timeout: 5 seconds
echo.

choice /C YN /N /T 5 /D Y /M "[Y/N]"

if errorlevel 2 goto RWA_CANCEL_FIRST

echo.
echo [OK] Removal confirmed.
goto RWA_CHECK_ADMIN


:RWA_CANCEL_FIRST
echo.
echo [!] Operation cancelled by the user.
echo [INFO] Skipping RemoveWindowsAI module.
goto RWA_CONTINUE


:: ------------------------------------------------
:: CHECK ADMINISTRATOR PRIVILEGES
:: ------------------------------------------------

:RWA_CHECK_ADMIN
echo.
echo [INFO] Checking administrator privileges...

net session >nul 2>&1
if errorlevel 1 (
    echo [X] Please run this module as Administrator.
    echo [INFO] Skipping RemoveWindowsAI module.
    goto RWA_CONTINUE
)

echo [OK] Administrator privileges confirmed.


:: ------------------------------------------------
:: DOWNLOAD OFFICIAL REMOVE WINDOWS AI SCRIPT
:: ------------------------------------------------

echo.
echo [DOWNLOAD] Downloading RemoveWindowsAI...

set "AI_SCRIPT=%TEMP%\RemoveWindowsAi.ps1"
set "AI_URL=https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1"

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command ^
 "try { $ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '%AI_URL%' -OutFile '%AI_SCRIPT%' -ErrorAction Stop; if (!(Test-Path '%AI_SCRIPT%') -or (Get-Item '%AI_SCRIPT%').Length -lt 1000) { throw 'Downloaded script is missing or invalid.' } } catch { Write-Host ('Download failed: ' + $_.Exception.Message) -ForegroundColor Red; exit 1 }"

if errorlevel 1 (
    echo [X] Download failed or the downloaded file is invalid.
    echo [INFO] Skipping RemoveWindowsAI module.
    goto RWA_CONTINUE
)

echo [OK] Download completed.


:: ------------------------------------------------
:: REMOVE SELECTED WARNINGS AND KEY PROMPTS
:: ------------------------------------------------

echo.
echo [INFO] Preparing AI cleanup...

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command ^
 "$p='%AI_SCRIPT%'; try { $c=Get-Content -LiteralPath $p -ErrorAction Stop; $c ^| Where-Object { $_ -notmatch 'Press Any Key to Continue' -and $_ -notmatch 'ReadKey' -and $_ -notmatch 'third-party anti-virus' -and $_ -notmatch 'may falsely block/break this script' } ^| Set-Content -LiteralPath $p -Encoding UTF8 -ErrorAction Stop } catch { Write-Host ('Failed to prepare script: ' + $_.Exception.Message) -ForegroundColor Red; exit 1 }"

if errorlevel 1 (
    echo [X] Failed to prepare the downloaded script.
    echo [INFO] Skipping RemoveWindowsAI module.
    goto RWA_CONTINUE
)

echo [OK] Script prepared.


:: ------------------------------------------------
:: SELECTED OPTIONS
:: ------------------------------------------------

echo.
echo [INFO] Selected options:
echo   - DisableRegKeys
echo   - DisableCopilotPolicies
echo   - RemoveAppxPackages
echo   - RemoveRecallFeature
echo   - HideAIComponents
echo   - DisableRewrite


:: ------------------------------------------------
:: SECOND CONFIRMATION - DEFAULT YES AFTER 5 SECONDS
:: ------------------------------------------------

echo.
echo Proceed with the selected changes?
echo Press Y to confirm or N to cancel.
echo Default: YES - Timeout: 5 seconds
echo.

choice /C YN /N /T 5 /D Y /M "[Y/N]"

if errorlevel 2 goto RWA_CANCEL_SECOND

echo.
echo [OK] Proceeding with selected changes.
goto RWA_RUN_SCRIPT


:RWA_CANCEL_SECOND
echo.
echo [!] Operation cancelled by the user.
echo [INFO] Skipping RemoveWindowsAI module.
goto RWA_CONTINUE


:: ------------------------------------------------
:: RUN USING WINDOWS POWERSHELL 5.1
:: ------------------------------------------------

:RWA_RUN_SCRIPT
echo.
echo [RUN] Launching Windows PowerShell 5.1...

set "RWA_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

if not exist "%RWA_PS%" (
    echo [X] Windows PowerShell 5.1 was not found.
    goto RWA_CONTINUE
)

:: Run the downloaded script with the selected options.
:: The child PowerShell process returns an exit code for status checking.

start "" /wait "%RWA_PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "& { & $env:AI_SCRIPT -NonInteractive -Options @('DisableRegKeys','DisableCopilotPolicies','RemoveAppxPackages','RemoveRecallFeature','HideAIComponents','DisableRewrite'); if ($?) { exit 0 } else { exit 1 } }"

set "RWA_EXIT_CODE=%ERRORLEVEL%"

if "%RWA_EXIT_CODE%"=="0" (
    echo.
    echo [OK] RemoveWindowsAI completed with exit code 0.
    echo [INFO] No execution record was created.
) else (
    echo.
    echo [!] RemoveWindowsAI returned exit code %RWA_EXIT_CODE%.
    echo [INFO] Review the output above before retrying.
)

goto RWA_CONTINUE


:: ------------------------------------------------
:: CONTINUE MAIN SCRIPT
:: ------------------------------------------------

:RWA_CONTINUE
echo.
echo --------------------------------------------------------
echo [INFO] RemoveWindowsAI module finished.
echo [INFO] Continuing with the next script...
echo --------------------------------------------------------
echo.

endlocal
exit
