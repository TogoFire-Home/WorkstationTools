@echo off
setlocal EnableExtensions

:: ==========================================
:: Check Administrator privileges
:: ==========================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WindowStyle Hidden"
    exit /b
)


:: ==========================================
:: Locate PowerShell 7
:: ==========================================

set "PW7="

:: Check standard MSI installation
if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" (
    set "PW7=%ProgramFiles%\PowerShell\7\pwsh.exe"
)

:: Check PATH
if not defined PW7 (
    for %%A in (pwsh.exe) do (
        set "PW7=%%~$PATH:A"
    )
)

:: Check Microsoft Store installation (WindowsApps)
if not defined PW7 (
    for /f "delims=" %%A in ('where pwsh.exe 2^>nul') do (
        set "PW7=%%A"
        goto :found_pw7
    )
)

:found_pw7

:: Fallback
if not defined PW7 (
    set "PW7=pwsh.exe"
)


:: ==========================================
:: Consumer ESU
:: ==========================================

"%PW7%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$url='https://github.com/abbodi1406/ConsumerESU/archive/refs/heads/master.zip'; $zip=Join-Path $env:TEMP 'ConsumerESU-master.zip'; $dir=Join-Path $env:TEMP 'ConsumerESU-master'; while($true){try{Invoke-WebRequest 'https://raw.githubusercontent.com' -Method Head -TimeoutSec 5 | Out-Null; break}catch{Start-Sleep -Seconds 5}}; Invoke-WebRequest $url -OutFile $zip; if(Test-Path $dir){Remove-Item $dir -Recurse -Force}; Expand-Archive $zip -DestinationPath $env:TEMP -Force; Start-Process cmd.exe -ArgumentList '/c Consumer_ESU_Enrollment_run.cmd' -WorkingDirectory $dir -Verb RunAs -WindowStyle Hidden -Wait"

exit /b 0
