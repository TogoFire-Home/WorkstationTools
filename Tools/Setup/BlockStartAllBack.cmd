@echo off
setlocal EnableExtensions
title Block StartAllBack Updates

:: ============================================================
:: CHECK ADMINISTRATOR PRIVILEGES
:: ============================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Requesting administrator privileges...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: ============================================================
:: LOCATE POWERSHELL 7
:: ============================================================

set "PW7="

for /f "usebackq delims=" %%A in (`powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$paths = Get-Command pwsh.exe -All -ErrorAction SilentlyContinue | ForEach-Object Source | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Sort-Object -Unique; $found = foreach ($path in $paths) { try { $v = & $path -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2^>$null; if ($v -match '^7\.') { [pscustomobject]@{ Version = [version]$v; Path = $path } } } catch {} }; $best = $found | Sort-Object Version -Descending | Select-Object -First 1; if ($best) { $best.Path }"`) do set "PW7=%%A"

if not defined PW7 if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" set "PW7=%ProgramFiles%\PowerShell\7\pwsh.exe"
if not defined PW7 if exist "%ProgramFiles(x86)%\PowerShell\7\pwsh.exe" set "PW7=%ProgramFiles(x86)%\PowerShell\7\pwsh.exe"

if not defined PW7 (
    echo [ERROR] PowerShell 7 was not found.
    pause
    exit /b 1
)

echo [INFO] PowerShell selected:
echo "%PW7%"
"%PW7%" -NoLogo -NoProfile -Command "$PSVersionTable.PSVersion.ToString()"

:: ============================================================
:: EXECUTE STARTALLBACK UPDATE BLOCKER
:: ============================================================

echo.
echo [INFO] Executing StartAllBack Update Blocker...

"%PW7%" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "try { Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force | Out-Null; Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/TogoFire-Home/WorkstationTools/main/Tools/Security/StartAllBack-Update-Blocker/Block-StartAllBack.ps1' -ErrorAction Stop) } catch { Write-Host ('[ERROR] ' + $_.Exception.Message) -ForegroundColor Red; exit 1 }"

set "RC=%ERRORLEVEL%"

echo.
if not "%RC%"=="0" (
    echo [ERROR] Script exited with code %RC%.
) else (
    echo [OK] Script finished.
)

exit /b %RC%
