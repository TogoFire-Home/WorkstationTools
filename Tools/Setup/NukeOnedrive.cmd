@echo off
setlocal EnableExtensions EnableDelayedExpansion
title OneDrive - Deep Uninstallation

echo.
echo ========================================================
echo           ONEDRIVE - DEEP UNINSTALLATION
echo ========================================================
echo.

:: --- Detect current Windows user ---
for %%U in ("%USERDOMAIN%\%USERNAME%") do set "CURRENT_USER=%%~nxU"

echo Current user: %USERNAME%
echo.

:: --- Start deep uninstallation automatically ---
echo -- Starting deep uninstallation of OneDrive...
echo.

:: --- Close OneDrive process ---
echo -- Closing OneDrive process...
taskkill /F /IM OneDrive.exe >nul 2>&1
timeout /T 2 /NOBREAK >nul

:: --- Official uninstallers ---
set "UNINSTALLER_X64=%SystemRoot%\SysWOW64\OneDriveSetup.exe"
set "UNINSTALLER_X86=%SystemRoot%\System32\OneDriveSetup.exe"

if exist "%UNINSTALLER_X64%" (
    echo -- Running official uninstaller...
    start "" /wait "%UNINSTALLER_X64%" /uninstall
) else if exist "%UNINSTALLER_X86%" (
    echo -- Running official uninstaller...
    start "" /wait "%UNINSTALLER_X86%" /uninstall
) else (
    echo -- OneDrive uninstaller not found. Continuing cleanup...
)

:: --- Migrate OneDrive files to user profile ---
echo -- Migrating OneDrive files...

if exist "%USERPROFILE%\OneDrive\" (
    robocopy "%USERPROFILE%\OneDrive" "%USERPROFILE%" /MOV /E /XJ /NDL /NFL /NJH /NJS /NC /NS /NP
)

:: --- Registry cleanup ---
echo -- Cleaning Explorer integration...

reg delete "HKCR\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >nul 2>&1
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\OneDrive" /f >nul 2>&1

:: --- Anti-reinstallation policies ---
echo -- Applying anti-reinstallation policies...

set "OD_POLICY=HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive"

reg add "%OD_POLICY%" /f >nul 2>&1
reg add "%OD_POLICY%" /v DisableFileSyncConfig /t REG_DWORD /d 1 /f >nul 2>&1
reg add "%OD_POLICY%" /v PreventNetworkUserAccounts /t REG_DWORD /d 1 /f >nul 2>&1

:: --- Cleanup shortcuts and startup entries ---
echo -- Removing shortcuts and startup entries...

del /F /Q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" >nul 2>&1

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSetup /f >nul 2>&1

:: --- Remove OneDrive scheduled tasks ---
echo -- Removing OneDrive scheduled tasks...

for /f "delims=" %%T in ('powershell.exe -NoProfile -Command "Get-ScheduledTask -TaskName 'OneDrive*' -ErrorAction SilentlyContinue | ForEach-Object { $_.TaskPath + $_.TaskName }" 2^>nul') do (
    schtasks /Delete /TN "%%T" /F >nul 2>&1
)

:: --- Remove leftover folders ---
echo -- Removing leftover folders...

if exist "%USERPROFILE%\OneDrive" (
    rmdir /S /Q "%USERPROFILE%\OneDrive" >nul 2>&1
)

if exist "%LOCALAPPDATA%\OneDrive" (
    rmdir /S /Q "%LOCALAPPDATA%\OneDrive" >nul 2>&1
)

if exist "%LOCALAPPDATA%\Microsoft\OneDrive" (
    rmdir /S /Q "%LOCALAPPDATA%\Microsoft\OneDrive" >nul 2>&1
)

if exist "%ProgramData%\Microsoft OneDrive" (
    rmdir /S /Q "%ProgramData%\Microsoft OneDrive" >nul 2>&1
)

if exist "C:\OneDriveTemp" (
    rmdir /S /Q "C:\OneDriveTemp" >nul 2>&1
)

echo.
echo -- OneDrive removal and cleanup completed.
echo.

:: --- Fix OneDrive launch / force-close policy ---
echo --------------------------------------------------------
echo -- Updating OneDrive policy...

set "OD_POLICY=HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive"

reg add "%OD_POLICY%" /f >nul 2>&1
reg add "%OD_POLICY%" /v DisableFileSyncNGSC /t REG_DWORD /d 0 /f >nul 2>&1

if errorlevel 1 (
    echo [WARNING] Could not update the policy. Run as administrator.
) else (
    echo [OK] OneDrive policy updated successfully.
)

echo.
echo ========================================================
echo                  OPERATION FINISHED
echo ========================================================
echo.

endlocal
#exit /b
exit
