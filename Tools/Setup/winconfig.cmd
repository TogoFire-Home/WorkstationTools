@echo off
setlocal EnableExtensions

title Windows Configuration - Edge, Desktop Icons and Printers

echo ========================================================
echo  WINDOWS CONFIGURATION
echo  Edge, Desktop Icons, Printers and User Folders
echo ========================================================
echo.

:: ========================================================
:: 1. MICROSOFT EDGE UNINSTALLATION
:: ========================================================

echo [MODULE 1] Uninstalling Microsoft Edge...

:: Enable Edge uninstallation through the registry
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev" ^
    /v AllowUninstall /t REG_DWORD /d 1 /f >nul 2>&1

:: Locate the official Microsoft Edge setup installer
set "EDGE_SETUP="

for /d %%V in ("%ProgramFiles(x86)%\Microsoft\Edge\Application\*") do (
    if exist "%%~fV\Installer\setup.exe" (
        set "EDGE_SETUP=%%~fV\Installer\setup.exe"
    )
)

if defined EDGE_SETUP (
    echo [INFO] Edge installer found.
    echo [INFO] Executing forced uninstallation...

    :: Create legacy Edge placeholder file, as in the original script
    if exist "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\" (
        if not exist "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe" (
            type nul > "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe" 2>nul
        )
    )

    :: Force-uninstall Edge and delete its profile
    start "" /wait "%EDGE_SETUP%" --uninstall --system-level --force-uninstall --delete-profile

    echo.
    echo [INFO] Cleaning up Microsoft Edge shortcuts...

    if exist "%PUBLIC%\Desktop\Microsoft Edge.lnk" (
        del /f /q "%PUBLIC%\Desktop\Microsoft Edge.lnk" >nul 2>&1
    )

    if exist "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" (
        del /f /q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" >nul 2>&1
    )

    if exist "%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk" (
        del /f /q "%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk" >nul 2>&1
    )

    if exist "%USERPROFILE%\Desktop\Microsoft Edge.lnk" (
        del /f /q "%USERPROFILE%\Desktop\Microsoft Edge.lnk" >nul 2>&1
    )

    echo [OK] Edge uninstallation command completed.
    echo [INFO] Verify the result if Edge remains installed.
) else (
    echo [WARNING] Microsoft Edge setup.exe was not found.
    echo [INFO] Skipping Edge uninstallation.
)

echo.
echo --------------------------------------------------------
echo.

:: ========================================================
:: 2. HIDE DESKTOP SYSTEM ICONS
:: ========================================================

echo [MODULE 2] Hiding desktop system icons...

set "HIDE_NEW=HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
set "HIDE_CLASSIC=HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"

:: Recycle Bin
reg add "%HIDE_NEW%" /v "{645FF040-5081-101B-9F08-00AA002F954E}" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "%HIDE_CLASSIC%" /v "{645FF040-5081-101B-9F08-00AA002F954E}" /t REG_DWORD /d 1 /f >nul 2>&1
echo [OK] Recycle Bin hidden.

:: Control Panel
reg add "%HIDE_NEW%" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "%HIDE_CLASSIC%" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d 1 /f >nul 2>&1
echo [OK] Control Panel hidden.

:: This PC
reg add "%HIDE_NEW%" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "%HIDE_CLASSIC%" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 1 /f >nul 2>&1
echo [OK] This PC hidden.

:: User Folder
reg add "%HIDE_NEW%" /v "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "%HIDE_CLASSIC%" /v "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" /t REG_DWORD /d 1 /f >nul 2>&1
echo [OK] User Folder hidden.

echo [INFO] Desktop changes may require refreshing Explorer.
echo.
echo --------------------------------------------------------
echo.

:: ========================================================
:: 3. PIN CLASSIC PRINTERS TO FILE EXPLORER NAVIGATION PANE
:: ========================================================

echo [MODULE 3] Registering Classic Printers in File Explorer...

set "PRINTERS_KEY=HKCU\Software\Classes\CLSID\{2227A280-3AEA-1069-A2DE-08002B30309D}"
set "PRINTERS_INPROC=%PRINTERS_KEY%\InProcServer32"
set "PRINTERS_ICON=%PRINTERS_KEY%\DefaultIcon"
set "PRINTERS_NAMESPACE=HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{2227A280-3AEA-1069-A2DE-08002B30309D}"

:: Create CLSID and set its default name
reg add "%PRINTERS_KEY%" /ve /t REG_SZ /d "Printers" /f >nul 2>&1

:: Register namespace visibility and sort order
reg add "%PRINTERS_KEY%" /v "System.IsPinnedToNamespaceTree" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "%PRINTERS_KEY%" /v "SortOrderIndex" /t REG_DWORD /d 60 /f >nul 2>&1

:: Register localized name and tooltip
reg add "%PRINTERS_KEY%" /v "LocalizedString" /t REG_EXPAND_SZ /d "@%SystemRoot%\System32\prnfldr.dll,-8036" /f >nul 2>&1
reg add "%PRINTERS_KEY%" /v "InfoTip" /t REG_EXPAND_SZ /d "@%SystemRoot%\System32\prnfldr.dll,-8062" /f >nul 2>&1

:: Register the COM server
reg add "%PRINTERS_INPROC%" /ve /t REG_EXPAND_SZ /d "%SystemRoot%\System32\prnfldr.dll" /f >nul 2>&1
reg add "%PRINTERS_INPROC%" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f >nul 2>&1

:: Set the default icon
reg add "%PRINTERS_ICON%" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\imageres.dll,-26" /f >nul 2>&1

:: Register in Explorer namespace
reg add "%PRINTERS_NAMESPACE%" /ve /t REG_SZ /d "Printers" /f >nul 2>&1

:: Hide the separate Printers desktop icon
reg add "%HIDE_NEW%" /v "{2227A280-3AEA-1069-A2DE-08002B30309D}" /t REG_DWORD /d 1 /f >nul 2>&1

echo [OK] Classic Printers registry entries created.
echo [OK] Printers registered in Explorer namespace.
echo.
echo --------------------------------------------------------
echo.

:: ========================================================
:: 4. ADD USER FOLDERS UNDER THIS PC IN FILE EXPLORER
:: ========================================================

echo [MODULE 4] Adding user folders under This PC...

set "NAMESPACE=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"

:: Desktop
call :ConfigureFolder "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" "Desktop"

:: Documents
call :ConfigureFolder "{d3162b92-9365-467a-956b-92703aca08af}" "Documents"

:: Downloads
call :ConfigureFolder "{088e3905-0323-4b02-9826-5d99428e115f}" "Downloads"

:: Music
call :ConfigureFolder "{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" "Music"

:: Pictures
call :ConfigureFolder "{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" "Pictures"

:: Videos
call :ConfigureFolder "{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" "Videos"

:: OPTIONAL: Remove Recycle Bin from This PC
:: reg delete "%NAMESPACE%\{645FF040-5081-101B-9F08-00AA002F954E}" /f

:: OPTIONAL: Remove Classic Printers from This PC
:: reg delete "%NAMESPACE%\{2227A280-3AEA-1069-A2DE-08002B30309D}" /f

echo.
echo [OK] User folders configured.
echo.
echo ========================================================
echo  WINDOWS CONFIGURATION COMPLETED
echo ========================================================
echo.

endlocal
goto :EOF

:: ========================================================
:: SUBROUTINE: CONFIGURE USER FOLDER
:: ========================================================

:ConfigureFolder
set "GUID=%~1"
set "FOLDERNAME=%~2"
set "KEY=%NAMESPACE%\%GUID%"

:: Create the registry key if it does not exist
reg add "%KEY%" /f >nul 2>&1

:: Remove HideIfEnabled to allow the folder to appear
reg delete "%KEY%" /v "HideIfEnabled" /f >nul 2>&1

:: Set HiddenByDefault to 0 (visible)
reg add "%KEY%" /v "HiddenByDefault" /t REG_DWORD /d 0 /f >nul 2>&1

echo [OK] %FOLDERNAME% configured.
#exit /b
exit
