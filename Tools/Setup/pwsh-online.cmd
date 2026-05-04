@echo off
setlocal EnableExtensions
title PowerShell 7 Bootstrapper

echo ============================================================
echo  POWERSHELL 7 BOOTSTRAPPER
echo  Automatic Installation and Explorer Context Menus
echo ============================================================
echo.

set "PWSH="

:: ------------------------------------------------------------
:: 1. CHECK FOR POWERSHELL 7
:: ------------------------------------------------------------

where pwsh.exe >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%P in ('where pwsh.exe 2^>nul') do (
        if not defined PWSH set "PWSH=%%P"
    )
)

if not defined PWSH if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" (
    set "PWSH=%ProgramFiles%\PowerShell\7\pwsh.exe"
)

if not defined PWSH if exist "%ProgramFiles(x86)%\PowerShell\7\pwsh.exe" (
    set "PWSH=%ProgramFiles(x86)%\PowerShell\7\pwsh.exe"
)

if not defined PWSH if exist "%LOCALAPPDATA%\Programs\PowerShell\7\pwsh.exe" (
    set "PWSH=%LOCALAPPDATA%\Programs\PowerShell\7\pwsh.exe"
)

if defined PWSH goto RUN_CORETOOLS

:: ------------------------------------------------------------
:: 2. DOWNLOAD AND INSTALL POWERSHELL 7 MSI
:: ------------------------------------------------------------

echo [INFO] PowerShell 7 not found.
echo [INFO] Downloading the latest official MSI...
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; try { $r=Invoke-RestMethod -Uri 'https://api.github.com/repos/PowerShell/PowerShell/releases/latest' -Headers @{'User-Agent'='Mozilla/5.0'}; if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { $a='arm64' } elseif ([Environment]::Is64BitOperatingSystem) { $a='x64' } else { $a='x86' }; $asset=$r.assets | Where-Object { $_.name -match ('win-' + $a + '\.msi$') } | Select-Object -First 1; if (-not $asset) { throw ('No MSI found for architecture ' + $a) }; $msi=Join-Path $env:TEMP 'PowerShell_Install.msi'; Write-Host ('[INFO] Package: ' + $asset.name); Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $msi -UseBasicParsing; if (-not (Test-Path $msi) -or (Get-Item $msi).Length -eq 0) { throw 'Downloaded MSI is missing or empty.' }; Write-Host '[INFO] Installing PowerShell 7 and Explorer context menus...'; $args=@('/i',('"' + $msi + '"'),'/quiet','/norestart','ADD_PATH=1','REGISTER_MANIFEST=1','DISABLE_TELEMETRY=1','ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1','ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1'); $p=Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -Wait -PassThru; if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw ('MSI installation failed. Exit code: ' + $p.ExitCode) }; Write-Host ('[OK] MSI completed. Exit code: ' + $p.ExitCode); exit 0 } catch { Write-Error $_; exit 1 } finally { if ($msi -and (Test-Path $msi)) { Remove-Item $msi -Force -ErrorAction SilentlyContinue } }"

if errorlevel 1 (
    echo.
    echo [ERROR] PowerShell 7 installation failed.
    echo [INFO] Check administrator privileges and internet access.
    echo.
    goto FINISH
)

:: ------------------------------------------------------------
:: 3. LOCATE THE NEW INSTALLATION
:: ------------------------------------------------------------

set "PWSH="

where pwsh.exe >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%P in ('where pwsh.exe 2^>nul') do (
        if not defined PWSH set "PWSH=%%P"
    )
)

if not defined PWSH if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" (
    set "PWSH=%ProgramFiles%\PowerShell\7\pwsh.exe"
)

if not defined PWSH if exist "%ProgramFiles(x86)%\PowerShell\7\pwsh.exe" (
    set "PWSH=%ProgramFiles(x86)%\PowerShell\7\pwsh.exe"
)

if not defined PWSH if exist "%LOCALAPPDATA%\Programs\PowerShell\7\pwsh.exe" (
    set "PWSH=%LOCALAPPDATA%\Programs\PowerShell\7\pwsh.exe"
)

if not defined PWSH (
    echo [ERROR] PowerShell 7 was not found after installation.
    goto FINISH
)


:: ------------------------------------------------------------
:: 4. FINISH
:: ------------------------------------------------------------

:FINISH
echo.
echo ============================================================
echo  BOOTSTRAPPER FINISHED
echo ============================================================
echo.
endlocal
exit
