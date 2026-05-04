@echo off
setlocal EnableExtensions
title CoreTools - PowerShell 7

:: Check administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Requesting administrator privileges...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: Locate PowerShell 7 and select the highest installed version
set "PW7="

for /f "usebackq delims=" %%A in (`powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$paths = Get-Command pwsh.exe -All -ErrorAction SilentlyContinue | ForEach-Object Source | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Sort-Object -Unique; $found = foreach ($path in $paths) { try { $v = & $path -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2^>$null; if ($v -match '^7\.') { [pscustomobject]@{ Version = [version]$v; Path = $path } } } catch {} }; $best = $found | Sort-Object Version -Descending | Select-Object -First 1; if ($best) { $best.Path }"`) do set "PW7=%%A"

if not defined PW7 if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" set "PW7=%ProgramFiles%\PowerShell\7\pwsh.exe"
if not defined PW7 if exist "%ProgramFiles(x86)%\PowerShell\7\pwsh.exe" set "PW7=%ProgramFiles(x86)%\PowerShell\7\pwsh.exe"

if not defined PW7 (
    echo [ERROR] PowerShell 7 was not found.
    pause
    exit /b 1
)

echo [INFO] Selected PowerShell:
echo "%PW7%"
"%PW7%" -NoLogo -NoProfile -Command "$PSVersionTable.PSVersion.ToString()"

:: Run CoreTools
echo.
echo [INFO] Waiting for internet connection...

"%PW7%" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "try { while ($true) { try { Invoke-WebRequest -Uri 'https://github.com' -Method Head -TimeoutSec 5 -ErrorAction Stop | Out-Null; break } catch { Start-Sleep -Seconds 3 } }; Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/TogoFire-Home/WorkstationTools/main/CoreTools.ps1' -ErrorAction Stop) } catch { Write-Host ('[ERROR] ' + $_.Exception.Message) -ForegroundColor Red; exit 1 }"

set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" (
    echo [ERROR] CoreTools exited with code %RC%.
) else (
    echo [OK] CoreTools finished.
)

exit /b %RC%
