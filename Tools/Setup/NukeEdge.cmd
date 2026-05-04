@echo off
setlocal EnableExtensions

title Microsoft Edge Uninstaller

echo --------------------------------------------------------
echo Initializing Microsoft Edge uninstallation...
echo --------------------------------------------------------

:: 1. Enable uninstallation flag in Registry
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev" /v AllowUninstall /t REG_DWORD /d 1 /f >nul 2>&1

:: 2. Locate the official Microsoft Edge setup installer
set "INSTALLER="

for /f "delims=" %%I in ('dir /b /s /a-d "C:\Program Files (x86)\Microsoft\Edge\Application\Installer\setup.exe" 2^>nul') do (
    if not defined INSTALLER set "INSTALLER=C:\Program Files (x86)\Microsoft\Edge\Application\%%I"
)

:: Correctly resolve the installer path by searching version folders
if not defined INSTALLER (
    for /d %%V in ("C:\Program Files (x86)\Microsoft\Edge\Application\*") do (
        if exist "%%~fV\Installer\setup.exe" (
            set "INSTALLER=%%~fV\Installer\setup.exe"
            goto :InstallerFound
        )
    )
)

:InstallerFound

if not defined INSTALLER (
    echo Error: Edge setup.exe not found. Skipping.
    goto :Cleanup
)

:: 3. Create legacy Edge placeholder file
if not exist "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" (
    mkdir "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" >nul 2>&1
)

if not exist "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe" (
    type nul > "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe" 2>nul
)

:: 4. Uninstall Microsoft Edge silently
echo Uninstalling Microsoft Edge...
start /wait "" "%INSTALLER%" --uninstall --system-level --force-uninstall --delete-profile

:Cleanup

:: 5. Remove residual shortcuts
del /f /q "%PUBLIC%\Desktop\Microsoft Edge.lnk" >nul 2>&1
del /f /q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" >nul 2>&1
del /f /q "%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk" >nul 2>&1
del /f /q "%USERPROFILE%\Desktop\Microsoft Edge.lnk" >nul 2>&1

echo.
echo Microsoft Edge uninstallation process completed.
echo --------------------------------------------------------

endlocal
exit /b
