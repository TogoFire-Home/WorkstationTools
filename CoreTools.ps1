# This script automates Windows post-installation setup, including system performance 
# optimizations, telemetry removal, and the automated deployment of development 
# tools via Winget and Chocolatey.

# KEY FEATURES:
# 1.  Session Setup: Configures execution policy to [Bypass] for the current process.
# 2.  Legacy Cleanup: Silently scans and removes old CMD/PowerShell registry entries if present.
# 3.  Context Menus: Adds multi-language CMD & PowerShell prompts (Shift + Right-click) with UNC path support.
# 4.  Advanced Desktop Tools: Adds a categorized menu for Control Panel, Safe Mode, Task Killer, and Explorer Restart.
# 5.  Boot Optimization: Procedural BCD/Registry fix to uncheck 'Number of Processors' in MSConfig to prevent instability and thermal throttling.
# 6.  System Performance: Enables automatic Pagefile management and removes QoS bandwidth limits.
# 7.  Explorer Tweaks: Hides Desktop Recycle Bin and pins it to the Explorer Sidebar for a cleaner workspace.
# 8.  Visuals & Login: Sets 100% Wallpaper quality, enables NumLock on login, and synchronizes SecPol for No-CTRL+ALT+DEL.
# 9.  File Handling: Restores 'New Text Document' and Script templates (.ps1, .reg, .bat, vbs, cmd) to the context menu.
# 10. Windows Updates: Hard-disables forced Driver updates and Microsoft's monthly bloatware "gift"—the useless Malicious Software Removal Tool (MRT).
# 11. SvcHost Optimization: Implements dynamic RAM-based SvcHost grouping (Split Threshold) to reduce process overhead.
# 12. App Management: Disables Background Apps globally to save CPU/RAM.
# 13. Update Freeze: Hard-pauses Windows Updates until the year 3000.
# 14. Version-Specific: Adds 'Check Ownership' menu (for Windows 26H1+ / non-25H2).
# 15. Universal Take Ownership: Deploys a 22-language "Take Ownership" menu using a high-compatibility .reg import method with orange checkmark icons.
# 16. Power Management: Disables network connectivity during Modern Standby (AC) to prevent "Sleep-to-Wake" drain.
# 17. Telemetry & Gaming: Disables Mouse acceleration, Office/PS telemetry, and Game Bar.
# 18. OneDrive removal: Deep uninstallation with data migration and 5s timeout.
# 19. Core Package Managers: Automated install/update of Chocolatey, Winget, and PS7.
# 20. Software Deployment: Installs dev tools and utilities via Choco (with Python/Dart pathing).
# 21. Optional Scripts: Digital Entitlement (MAS) and StartAllBack blocker with 5s skip.
# 22. Registry Fixes: Alt+Tab (Show 20 Edge Tabs), Explorer starts at 'This PC', and No Auto-Reboot.
# 23. Context Limit: Increases the right-click "Multiple Files" selection limit to 128 items.
# 24. Shell Folders: Restores all User Folders (Downloads, Documents, etc.) directly under 'This PC'.
# 25. Browser Debloat: Disables Telemetry, AI (Copilot/Leo), and Bloat for Chrome, Brave, Edge & Firefox.
# 26. Network/DNS: Optimizes DNS Cache TTL and table size for faster web resolution.
# 27. Python Ecosystem: Automated pip upgrade and Hugging Face CLI (HF-CLI) deployment.
# 28. Startup Manager: Disables Steam, Discord, Teams, and others via binary status (03) in Registry.
# 29. Winget Deployment: Interactive setup for Communication, Security, and AI tools via Store IDs with 5s popups.
# 30. Gaming Essentials: One-click pack (Steam, Discord, EA, Epic, Xbox) with automated Store ID matching.
# 31. GitHub Env: Sets NTFS protection to false and enables Case Sensitivity on specialized development folders.
# 32. Git Optimization: Migrates Git Bash and Git GUI context menu items to 'Shift + Right Click' to reduce clutter.
# 33. User Security: Force-sets 'Password Never Expires' for the Admin account.
# 34. Crash Analysis: Enables Detailed BSOD (DisplayParameters) for technical info.
# 35. Print Spooler ACL: Universal SID (S-1-1-0) Full Control grant for 'Everyone'.
# 36. Spooler Context Menu: 22-language repair tool deployed to C:\Windows.
# 37. Visual Effects: Enforced "Show thumbnails" and "Desktop icon shadows".
# 38. Media Extensions: Auto-update for HEVC (Free-Codecs) and 8 Codecs extensions.
# 39. Advanced Thumbnailing: Automated GitHub deployment for Icaros Thumbnailer.
# 40. Context Menu Purge: High-speed registry cleanup to remove grepWin shell entries using native reg.exe for zero-lag execution.
# 41. Explorer UI Opt: Windows 11-specific Snap Layouts enablement and smart Quick Access management. Disables automatic frequent folders and provides an interactive 5s prompt to clear cache only if requested, preserving manual pins.
# 42. Start Menu Refactor: Automated renaming of 'XTools' to 'Tools' with recursive cleanup of redundant PhoenixOS shortcuts and folders.
# 43. Volume Identity: Force-sets System Drive (C:) label to "Windows" and purges localized "Extras + Info" desktop clutter.

# --- APPENDIX: LEGACY EXECUTION POLICY SETTINGS (DISABLED) ---
# The following section is kept for reference only. 
# Current logic uses '-Scope Process' to avoid permanent system changes.

<#
# --- Original Execution Policy Setup ---
# This was used to set 'Unrestricted' policy for the CurrentUser.
# Write-Host "Setting PowerShell execution policy to Unrestricted for the current user..."
# Set-ExecutionPolicy -Scope CurrentUser Unrestricted -Force >$null 2>&1

# --- Original Revert Logic ---
# This was used at the end of the script to restore policy to RemoteSigned.
# Write-Host "Reverting PowerShell execution policy to RemoteSigned for current user..."
# Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force >$null 2>&1
# Write-Host "Execution policy set to RemoteSigned for current user."
# Write-Host "Software setup and installation completed successfully! ✅"
#>
# --------------------------------------------------------------

# --- 0. Setup: Ensure Execution Policy is permissive for this session ---
Write-Host "Configuring session execution policy..." -ForegroundColor Cyan

# Using -Scope Process ensures it only affects this current session
# and doesn't trigger GPO/Administrator overrides or warnings.
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force | Out-Null
    Write-Host "Execution policy set to [Bypass] for current session. ✅" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not set execution policy, but continuing..." -ForegroundColor Yellow
}

# Gets the directory where this script (.ps1) is being executed.
# $PSScriptRoot is an automatic PowerShell variable that holds the full path of the current script's directory.
$scriptDir = $PSScriptRoot

##------------------------------------------------------##

<# 
[MODULE] EXPLORER & UI OPTIMIZATION (Windows 11+)
Description: Enhances Windows Explorer performance and aesthetics by managing Snap Layouts, 
             Quick Access behavior, and cleaning system telemetry/junk.
Compatibility: Windows 11 (Build 22000+) or higher.
#>

# Verify if the current operating system is Windows 11
$winVersion = [Environment]::OSVersion.Version
if ($winVersion.Major -ge 10 -and $winVersion.Build -ge 22000) {
    Write-Host "`n[MODULE] Optimizing Windows Explorer UI (Windows 11 Detected)..." -ForegroundColor Cyan
    Write-Host "----------------------------------------------------------------" -ForegroundColor Gray

    # 1. Enable Snap Layouts (Snap Assist Flyout)
    # Ensures the Snap Layouts menu appears when hovering over the window maximize button.
    Write-Host "-- Enabling Snap Layouts..." -ForegroundColor Gray
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    if (!(Test-Path $registryPath)) { New-Item -Path $registryPath -Force | Out-Null }
    Set-ItemProperty -Path $registryPath -Name "EnableSnapAssistFlyout" -Value 1 -Type DWord

    # 2. Disable Automatic Frequent Folders & Recent Files
    # Forces Quick Access to display exclusively manually pinned folders for a cleaner experience.
    Write-Host "-- Configuring Quick Access to show ONLY manual pins..." -ForegroundColor Gray
    $explorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    Set-ItemProperty -Path $explorerPath -Name "ShowFrequent" -Value 0 -Type DWord
    Set-ItemProperty -Path $explorerPath -Name "ShowRecent" -Value 0 -Type DWord

    # 3. Clean Quick Access Cache (Interactive Maintenance)
    # Targets the 'f01b4d95...' database to resolve Explorer lag or hangs.
    # Note: Deleting this file will reset all user-pinned folders to defaults.
    $qaCache = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms"
    if (Test-Path $qaCache) {
        $msgTitle = "Quick Access Maintenance"
        $msgText = "Do you want to reset Quick Access cache?`n`nThis is a specific fix for Explorer hangs/lag, but it will REMOVE all your pinned folders.`n`n(Auto-skipping in 5 seconds...)"
        
        # Deploy a WScript.Shell Popup with a 5-second timeout (Value 4 = Yes/No, 32 = Question Mark)
        $shell = New-Object -ComObject WScript.Shell
        $response = $shell.Popup($msgText, 5, $msgTitle, 4 + 32)

        if ($response -eq 6) { # User clicked 'Yes'
            Write-Host "-- Cleaning Quick Access cache..." -ForegroundColor Yellow
            Remove-Item $qaCache -Force -ErrorAction SilentlyContinue
            Write-Host "[OK] Quick Access reset successfully." -ForegroundColor Green
        } else {
            Write-Host "[SKIP] Quick Access cache preserved (User choice or Timeout)." -ForegroundColor Yellow
        }
    }

    # 4. Clean Jump Lists & App History (Retention: 3 Days)
    # Scans Automatic and Custom Destinations to remove stale history entries.
    # Logic: Specifically excludes the Quick Access pinned database from this bulk deletion.
    Write-Host "-- Cleaning Jump Lists and History (Keeping Manual Pins)..." -ForegroundColor Gray
    $recentPaths = @(
        "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations",
        "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
    )
    foreach ($p in $recentPaths) {
        if (Test-Path $p) {
            Get-ChildItem -Path $p -File -Recurse -Force | 
            Where-Object { 
                $_.LastWriteTime -lt (Get-Date).AddDays(-3) -and 
                $_.Name -ne "f01b4d95cf55d32a.automaticDestinations-ms" 
            } | 
            ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
        }
    }

    # 5. Empty Recycle Bin (Silent)
    # Permanently removes deleted items from the Recycle Bin on all drives.
    # This action is silent and does not require user confirmation.
    Write-Host "-- Emptying Recycle Bin..." -ForegroundColor Gray
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue

    # 6. Refresh Interface Processes (Light Shell Refresh)
    # Terminates non-critical shell components to apply registry changes without a full Explorer restart.
    Write-Host "-- Refreshing Shell Components..." -ForegroundColor Yellow
    $uiProcesses = @("SearchHost", "ShellExperienceHost", "StartMenuExperienceHost")
    foreach ($proc in $uiProcesses) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    Write-Host "`n[SUCCESS] UI Optimization completed! ✅" -ForegroundColor Green
    Write-Host "----------------------------------------------------------------" -ForegroundColor Gray
} else {
    Write-Host "`n[SKIP] UI Optimization: System is not Windows 11. ⏩" -ForegroundColor Yellow
}

##------------------------------------------------------##

# --- Custom System & Folder Management ---
Write-Host "`n[MODULE] Running System Maintenance & Cleanup..." -ForegroundColor Cyan
Write-Host "--------------------------------------------------------" -ForegroundColor Gray

# 1. Rename XTools to Tools (Start Menu)
$xLitePath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\X-Lite Tools"
$toolsPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Tools"

if (Test-Path $xLitePath) {
    Write-Host "-- Found 'XTools'. Renaming to 'Tools'..." -ForegroundColor Gray
    try {
        Rename-Item -Path $xLitePath -NewName "Tools" -Force -ErrorAction Stop
        Write-Host "[OK] Folder renamed to Tools." -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Could not rename folder: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[SKIP] 'XTools' not found or already renamed." -ForegroundColor Yellow
}

# 2. Remove PhoenixOS Core Folders (ProgramData)
$phoenixFolders = @(
    "C:\ProgramData\PhoenixOS\WinaeroTweaker",
    "C:\ProgramData\PhoenixOS\Search"
)

foreach ($folder in $phoenixFolders) {
    if (Test-Path $folder) {
        Write-Host "-- Removing PhoenixOS folder: $folder" -ForegroundColor Gray
        Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Folder deleted." -ForegroundColor Green
    }
}

# 3. Remove Start Menu Shortcuts (The specific .lnk files)
# Added .lnk extension and wildcards to ensure they are deleted as files
$shortcutsToRemove = @(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Tools\Search.lnk",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Tools\Winaero Tweaker.lnk"
)

foreach ($shortcut in $shortcutsToRemove) {
    if (Test-Path $shortcut) {
        Write-Host "-- Removing Start Menu shortcut: $(Split-Path $shortcut -Leaf)" -ForegroundColor Gray
        Remove-Item -Path $shortcut -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Shortcut deleted." -ForegroundColor Green
    } else {
        # Double check without extension just in case
        $altPath = $shortcut.Replace(".lnk", "")
        if (Test-Path $altPath) {
            Remove-Item -Path $altPath -Force -ErrorAction SilentlyContinue
            Write-Host "[OK] Shortcut deleted (alt)." -ForegroundColor Green
        } else {
            Write-Host "[SKIP] Shortcut not found: $shortcut" -ForegroundColor Yellow
        }
    }
}

# 4. Remove Desktop Shortcut (Extras + Info)
$desktopLnk = "$env:USERPROFILE\Desktop\Extras + Info.lnk"
if (Test-Path $desktopLnk) {
    Write-Host "-- Removing Desktop shortcut: 'Extras + Info'..." -ForegroundColor Gray
    Remove-Item -Path $desktopLnk -Force
    Write-Host "[OK] Desktop shortcut deleted." -ForegroundColor Green
}

# 5. Move Compactor Shortcut to Tools Folder
$compactorSource = "$env:USERPROFILE\Desktop\Compactor (System Drive).lnk"
if (Test-Path $compactorSource) {
    if (Test-Path $toolsPath) {
        Write-Host "-- Moving 'Compactor' shortcut to Tools folder..." -ForegroundColor Gray
        Move-Item -Path $compactorSource -Destination $toolsPath -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Compactor shortcut moved successfully." -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Destination Tools folder not found. Shortcut stay on Desktop." -ForegroundColor Red
    }
} else {
    Write-Host "[SKIP] Compactor shortcut not found on Desktop." -ForegroundColor Yellow
}

# 6. Rename Drive C: to "Windows"
$driveC = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = 'C:'"
if ($driveC) {
    if ($driveC.Label -ne "Windows") {
        Write-Host "-- Changing Drive C: label to 'Windows'..." -ForegroundColor Gray
        Set-CimInstance -InputObject $driveC -Property @{Label = "Windows"}
        Write-Host "[OK] Drive renamed." -ForegroundColor Green
    } else {
        Write-Host "[SKIP] Drive C: is already named 'Windows'." -ForegroundColor Green
    }
}

Write-Host "--------------------------------------------------------"
Write-Host "[SUCCESS] Maintenance Module Completed! ✅" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------"

##------------------------------------------------------##

<#
    [MODULE] CONTEXT MENU ENGINE & SYSTEM CORE TWEAKS
#>

Write-Host "`n[INIT] Launching Context Menu & System Core Module..." -ForegroundColor Cyan
Write-Host "--------------------------------------------------------" -ForegroundColor Gray

##------------------------------------------------------##

# --- Legacy Context Menu Cleanup Module ---
Write-Host "`n[MODULE] Checking for legacy CMD and PowerShell context menu entries..." -ForegroundColor Cyan

$keysToRemove = @(
    # CMD Menu Entries
    "HKEY_CLASSES_ROOT\Directory\shell\01MenuCmd",
    "HKEY_CLASSES_ROOT\Directory\background\shell\01MenuCmd",
    "HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuCmd",

    # PowerShell Menu Entries
    "HKEY_CLASSES_ROOT\Directory\shell\02MenuPowerShell",
    "HKEY_CLASSES_ROOT\Directory\background\shell\02MenuPowerShell",
    "HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPowerShell"
)

$removedCount = 0
$skippedCount = 0

foreach ($key in $keysToRemove) {
    $regPath = "Registry::$key"
    
    if (Test-Path $regPath) {
        try {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
            Write-Host "[SUCCESS] Removed: $key" -ForegroundColor Green
            $removedCount++
        }
        catch {
            Write-Host "[ERROR] Could not remove $key : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        # Silent skip or low-profile log
        Write-Host "[SKIP] Entry not present: $($key.Split('\')[-1])" -ForegroundColor Gray
        $skippedCount++
    }
}

Write-Host "`nCleanup Summary:" -ForegroundColor White
Write-Host ">> Entries Removed: $removedCount" -ForegroundColor Green
Write-Host ">> Entries Skipped: $skippedCount" -ForegroundColor Yellow
Write-Host "--------------------------------------------------------"

##------------------------------------------------------##

# --- Context Menu: Shell Extensions (Multi-Language & Shift-only) ---
Write-Host "`n[MODULE] Deploying Shell Context Menu Extensions (Shift-only)..." -ForegroundColor Cyan

# Detect system language (ISO 2-letter code)
$langID = (Get-Culture).TwoLetterISOLanguageName

# Multi-language dictionary for all 22 requested languages
$translations = @{
    "en" = @{ copy = "All rights reserved."; open = "Open here"; admin = "Open here as administrator" }
    "pt" = @{ copy = "Todos os direitos reservados."; open = "Abrir aqui"; admin = "Abrir aqui como administrador" }
    "es" = @{ copy = "Todos los derechos reservados."; open = "Abrir aquí"; admin = "Abrir aquí como administrador" }
    "de" = @{ copy = "Alle Rechte vorbehalten."; open = "Hier öffnen"; admin = "Hier als Administrator öffnen" }
    "nl" = @{ copy = "Alle rechten voorbehouden."; open = "Hier openen"; admin = "Hier openen als administrator" }
    "fr" = @{ copy = "Tous droits réservés."; open = "Ouvrir ici"; admin = "Ouvrir ici en tant qu'administrateur" }
    "it" = @{ copy = "Tutti i diritti riservati."; open = "Apri qui"; admin = "Apri qui come amministratore" }
    "ja" = @{ copy = "All rights reserved."; open = "ここで開く"; admin = "管理者としてここで開く" }
    "ko" = @{ copy = "모든 권리 보유."; open = "여기에서 열기"; admin = "관리자 권한으로 여기에서 열기" }
    "zh" = @{ copy = "版权所有。"; open = "在此处打开"; admin = "在此处以管理员身份打开" }
    "uk" = @{ copy = "Усі права захищені."; open = "Відкрити тут"; admin = "Відкрити тут від імені адміністратора" }
    "ru" = @{ copy = "Все права защищены."; open = "Открыть здесь"; admin = "Открыть здесь от имени администратора" }
    "bg" = @{ copy = "Всички права запазени."; open = "Отвори тук"; admin = "Отвори тук като администратор" }
    "hi" = @{ copy = "सर्वाधिकार सुरक्षित।"; open = "यहाँ खोलें"; admin = "प्रशासक के रूप में यहाँ खोलें" }
    "tr" = @{ copy = "Tüm hakları saklıdır."; open = "Burada aç"; admin = "Burada yönetici olarak aç" }
    "vi" = @{ copy = "Giữ toàn quyền bản quyền."; open = "Mở ở đây"; admin = "Mở ở đây với tư cách quản trị viên" }
    "th" = @{ copy = "สงวนลิขสิทธิ์."; open = "เปิดที่นี่"; admin = "เปิดที่นี่ในฐานะผู้ดูแลระบบ" }
    "id" = @{ copy = "Hak cipta dilindungi."; open = "Buka di sini"; admin = "Buka di sini sebagai administrator" }
    "ms" = @{ copy = "Hak cipta terpelihara."; open = "Buka di sini"; admin = "Buka di sini sebagai pentadbir" }
    "fi" = @{ copy = "Kaikki oikeudet pidätetään."; open = "Avaa tässä"; admin = "Avaa tässä järjestelmänvalvojana" }
    "he" = @{ copy = "כל הזכויות שמורות."; open = "פתח כאן"; admin = "פתח כאן כמנהל מערכת" }
    "el" = @{ copy = "Με επιφύλαξη παντός δικαιώματος."; open = "Άνοιγμα εδώ"; admin = "Άνοιγμα εδώ ως διαχειριστής" }
}

# Fallback to English if the language is not in the dictionary
$langSet = if ($translations.ContainsKey($langID)) { $translations[$langID] } else { $translations["en"] }
$copyText = $langSet.copy
$openText = $langSet.open
$adminText = $langSet.admin

# --- SECTION: COMMAND PROMPT (CMD) ---
Write-Host ">> Configuring Command Prompt Extensions..." -ForegroundColor Gray

$cmdPaths = @(
    "HKLM:\SOFTWARE\Classes\DesktopBackground\Shell\CommandPrompt",
    "HKLM:\SOFTWARE\Classes\Directory\background\shell\CommandPrompt",
    "HKLM:\SOFTWARE\Classes\Directory\shell\CommandPrompt",
    "HKLM:\SOFTWARE\Classes\Drive\shell\CommandPrompt"
)

foreach ($rootPath in $cmdPaths) {
    try {
        if (-not (Test-Path $rootPath)) { New-Item -Path $rootPath -Force | Out-Null }
        Set-ItemProperty -Path $rootPath -Name "Icon" -Value "imageres.dll,-5323" -Force
        Set-ItemProperty -Path $rootPath -Name "MUIVerb" -Value "Command Prompt" -Force
        Set-ItemProperty -Path $rootPath -Name "SubCommands" -Value "" -Force
        Set-ItemProperty -Path $rootPath -Name "Extended" -Value "" -Force

        $shellPath = "$rootPath\shell"
        if (-not (Test-Path $shellPath)) { New-Item -Path $shellPath -Force | Out-Null }
        $var = if ($rootPath -match "Directory\\shell" -or $rootPath -match "Drive\\shell") { "%L" } else { "%V" }

        # --- Sub-Option 1: Open Here (Normal CMD)
        $cmd1Path = "$shellPath\cmd1"
        # We delete and recreate to clear any English cache in the registry
        if (Test-Path $cmd1Path) { Remove-Item $cmd1Path -Recurse -Force }
        New-Item -Path $cmd1Path -Force | Out-Null
        
        # Explicitly setting the default value as the translated string
        Set-ItemProperty -Path $cmd1Path -Name "(Default)" -Value "$openText" -Force
        Set-ItemProperty -Path $cmd1Path -Name "Icon" -Value "imageres.dll,-5323" -Force

        $cmd1Command = "$cmd1Path\command"
        New-Item -Path $cmd1Command -Force | Out-Null
        $normalCmd = "cmd.exe /s /k `"pushd `"$var`" & ver & echo (c) Microsoft Corporation. $copyText & echo.`""
        Set-ItemProperty -Path $cmd1Command -Name "(Default)" -Value $normalCmd -Force

        # --- Sub-Option 2: Open Here as Administrator (CMD) ---
        $cmd2Path = "$shellPath\cmd2"
        if (-not (Test-Path $cmd2Path)) { New-Item -Path $cmd2Path -Force | Out-Null }
        Set-ItemProperty -Path $cmd2Path -Name "(Default)" -Value "$adminText" -Force
        Set-ItemProperty -Path $cmd2Path -Name "HasLUAShield" -Value "" -Force
        Set-ItemProperty -Path $cmd2Path -Name "Icon" -Value "imageres.dll,-5324" -Force

        $cmd2Command = "$cmd2Path\command"
        if (-not (Test-Path $cmd2Command)) { New-Item -Path $cmd2Command -Force | Out-Null }
        $innerCmd = "/k cd /d \`"$var\`" & ver & echo (c) Microsoft Corporation. $copyText & echo."
        $adminCmd = "powershell.exe -NoProfile -WindowStyle Hidden -Command `"Start-Process cmd.exe -ArgumentList '$innerCmd' -Verb RunAs`""
        Set-ItemProperty -Path $cmd2Command -Name "(Default)" -Value $adminCmd -Force

        Write-Host "[SUCCESS] CMD Submenu added: $($rootPath.Split('\')[-1])" -ForegroundColor Green
    } catch { Write-Host "[ERROR] Failed at CMD: $rootPath" -ForegroundColor Red }
}

# --- SECTION: WINDOWS POWERSHELL ---
Write-Host "`n>> Configuring Windows PowerShell Extensions..." -ForegroundColor Gray

$psPaths = @(
    "HKLM:\SOFTWARE\Classes\DesktopBackground\Shell\PowerShellMenu",
    "HKLM:\SOFTWARE\Classes\Directory\background\shell\PowerShellMenu",
    "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellMenu",
    "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellMenu"
)

foreach ($rootPath in $psPaths) {
    try {
        if (-not (Test-Path $rootPath)) { New-Item -Path $rootPath -Force | Out-Null }
        Set-ItemProperty -Path $rootPath -Name "Icon" -Value "powershell.exe" -Force
        Set-ItemProperty -Path $rootPath -Name "MUIVerb" -Value "Windows PowerShell" -Force
        Set-ItemProperty -Path $rootPath -Name "SubCommands" -Value "" -Force
        Set-ItemProperty -Path $rootPath -Name "Extended" -Value "" -Force 

        $shellPath = "$rootPath\shell"
        if (-not (Test-Path $shellPath)) { New-Item -Path $shellPath -Force | Out-Null }
        $var = if ($rootPath -match "Directory\\shell" -or $rootPath -match "Drive\\shell") { "%L" } else { "%V" }

        # --- Sub-Option 1: Open Here (Normal PowerShell) ---
        $ps1Path = "$shellPath\ps1"
        if (-not (Test-Path $ps1Path)) { New-Item -Path $ps1Path -Force | Out-Null }
        Set-ItemProperty -Path $ps1Path -Name "(Default)" -Value "$openText" -Force
        Set-ItemProperty -Path $ps1Path -Name "Icon" -Value "powershell.exe" -Force

        $ps1Command = "$ps1Path\command"
        if (-not (Test-Path $ps1Command)) { New-Item -Path $ps1Command -Force | Out-Null }
        $normalPs = 'powershell.exe -NoExit -Command "Set-Location -LiteralPath ''{0}''; Write-Host ''Windows PowerShell''; Write-Host ''(c) Microsoft Corporation. {1}''; Write-Host ''''"' -f $var, $copyText
        Set-ItemProperty -Path $ps1Command -Name "(Default)" -Value $normalPs -Force

        # --- Sub-Option 2: Open Here as Administrator (PowerShell) ---
        $ps2Path = "$shellPath\ps2"
        if (-not (Test-Path $ps2Path)) { New-Item -Path $ps2Path -Force | Out-Null }
        Set-ItemProperty -Path $ps2Path -Name "(Default)" -Value "$adminText" -Force
        Set-ItemProperty -Path $ps2Path -Name "HasLUAShield" -Value "" -Force
        Set-ItemProperty -Path $ps2Path -Name "Icon" -Value "powershell.exe" -Force

        $ps2Command = "$ps2Path\command"
        if (-not (Test-Path $ps2Command)) { New-Item -Path $ps2Command -Force | Out-Null }
        $innerPs = "Set-Location -LiteralPath ''{0}'' ; Write-Host ''Windows PowerShell'' ; Write-Host ''(c) Microsoft Corporation. {1}'' ; Write-Host ''''" -f $var, $copyText
        $adminPs = 'powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Process powershell.exe -ArgumentList ''-NoExit'', ''-Command'', ''{0}'' -Verb RunAs"' -f $innerPs
        Set-ItemProperty -Path $ps2Command -Name "(Default)" -Value $adminPs -Force

        Write-Host "[SUCCESS] PowerShell Submenu added: $($rootPath.Split('\')[-1])" -ForegroundColor Green
    } catch { Write-Host "[ERROR] Failed at PowerShell: $rootPath" -ForegroundColor Red }
}

Write-Host ""
Write-Host "Deployment Complete. Detected: $langID | Labels applied." -ForegroundColor Cyan
Write-Host "`--------------------------------------------------------"

##------------------------------------------------------##

# --- CUSTOM DESKTOP CONTEXT MENU MODULE (MULTI-LANGUAGE) ---
Write-Host "`n[MODULE] Adding Advanced Tools to Desktop Context Menu..." -ForegroundColor Cyan

# Detect system language
$langID = (Get-Culture).TwoLetterISOLanguageName
$basePath = "Registry::HKEY_CLASSES_ROOT\DesktopBackground\Shell"
$appliedCount = 0

# --- Translation Dictionary ---
$t = @{
    "ControlPanel"    = @{ "en"="Control Panel"; "pt"="Painel de Controle"; "es"="Panel de control"; "de"="Systemsteuerung"; "nl"="Configuratiescherm"; "fr"="Panneau de configuration"; "it"="Pannello di controllo"; "ja"="コントロール パネル"; "ko"="제어판"; "zh"="控制面板"; "uk"="Панель керування"; "ru"="Панель управления"; "bg"="Контролен панел"; "hi"="कंट्रोल पैनल"; "tr"="Denetim Masası"; "vi"="Bảng điều khiển"; "th"="แผงควบคุม"; "id"="Panel Kontrol"; "ms"="Panel Kawalan"; "fi"="Ohjauspaneeli"; "he"="לוח הבקרה"; "el"="Πίνακας Ελέγχου" }
    "CP_Cat"          = @{ "en"="Control Panel (Category)"; "pt"="Painel de Controle (Categoria)"; "es"="Panel de control (Categoría)"; "de"="Systemsteuerung (Kategorie)"; "fr"="Panneau de configuration (Catégorie)"; "ru"="Панель управления (Категория)"; "zh"="控制面板 (类别)" }
    "CP_Icons"        = @{ "en"="All Control Panel Items (Icons)"; "pt"="Todos os Itens (Ícones)"; "es"="Todos los elementos (Iconos)"; "de"="Alle Systemsteuerungselemente (Symbole)"; "fr"="Tous les menus (Icônes)"; "ru"="Все элементы управления (Значки)" }
    "GodMode"         = @{ "en"="All Tasks (God Mode)"; "pt"="Todas as Tarefas (God Mode)"; "es"="Todas las tareas (Modo Dios)"; "ru"="Все задачи (God Mode)" }
    "KillTasks"       = @{ "en"="Kill Unresponsive Tasks"; "pt"="Encerrar Processos Travados"; "es"="Finalizar tareas no respondidas"; "de"="Nicht reagierende Tasks beenden"; "fr"="Tuer les tâches qui ne répondent pas"; "ru"="Завершить зависшие задачи"; "zh"="结束未响应任务" }
    "SafeMode"        = @{ "en"="Safe Mode"; "pt"="Modo de Segurança"; "es"="Modo seguro"; "de"="Abgesicherter Modus"; "fr"="Mode sans échec"; "ja"="セーフモード"; "ru"="Безопасный режим"; "zh"="安全模式" }
    "SM_Normal"       = @{ "en"="Restart in Normal Mode"; "pt"="Reiniciar em Modo Normal"; "es"="Reiniciar en modo normal"; "fr"="Redémarrer en mode normal"; "ru"="Перезагрузка в обычном режиме" }
    "SM_Safe"         = @{ "en"="Restart in Safe Mode"; "pt"="Reiniciar em Modo de Segurança"; "es"="Reiniciar en modo seguro"; "fr"="Redémarrer en mode sans échec"; "ru"="Перезагрузка в безопасном режиме" }
    "SM_Net"          = @{ "en"="Restart in Safe Mode with Networking"; "pt"="Modo de Segurança com Rede"; "es"="Modo seguro con funciones de red"; "ru"="Безопасный режим с загрузкой сетевых драйверoв" }
    "SM_CMD"          = @{ "en"="Restart in Safe Mode with Command Prompt"; "pt"="Modo de Segurança com Prompt"; "es"="Modo seguro con símbolo del sistema"; "ru"="Безопасный режим com командной строкой" }
    "RestartExplorer" = @{ "en"="Restart Explorer"; "pt"="Reiniciar Explorer"; "es"="Reiniciar Explorer"; "de"="Explorer neu starten"; "fr"="Redémarrer l'Explorador"; "ru"="Перезапуск проводника" }
    "RE_Now"          = @{ "en"="Restart Explorer Now"; "pt"="Reiniciar Explorer Agora"; "es"="Reiniciar Explorer ahora"; "ru"="Перезапустить сейчас" }
    "RE_Pause"        = @{ "en"="Restart Explorer with Pause"; "pt"="Reiniciar Explorer com Pausa"; "es"="Reiniciar Explorer con pausa"; "ru"="Перезапустить com паузой" }
    "SysProp"         = @{ "en"="System Properties"; "pt"="Propriedades do Sistema"; "es"="Propriedades del sistema"; "de"="Systemeigenschaften"; "fr"="Propriétés système"; "ru"="Свойства системы"; "zh"="系统属性" }
}

function Get-T($key) {
    if ($t[$key].ContainsKey($langID)) { return $t[$key][$langID] } else { return $t[$key]["en"] }
}

function Quick-Reg {
    param ($Path, $Name, $Value, $Type = "String")
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

try {
    # 1. CONTROL PANEL
    $name = Get-T "ControlPanel"
    Write-Host ">> Applying: $name..." -ForegroundColor Gray
    $cp = "$basePath\ControlPanel"
    Quick-Reg $cp "MUIVerb" $name
    Quick-Reg $cp "SubCommands" ""
    Quick-Reg $cp "Icon" "imageres.dll,-27"
    Quick-Reg "$cp\shell\001flyout" "(Default)" (Get-T "CP_Cat")
    Quick-Reg "$cp\shell\001flyout\command" "(Default)" "explorer.exe shell:::{26EE0668-A00A-44D7-9371-BEB064C98683}"
    Quick-Reg "$cp\shell\002flyout" "(Default)" (Get-T "CP_Icons")
    Quick-Reg "$cp\shell\002flyout\command" "(Default)" "explorer.exe shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}"
    Quick-Reg "$cp\shell\003flyout" "(Default)" (Get-T "GodMode")
    Quick-Reg "$cp\shell\003flyout\command" "(Default)" "explorer.exe shell:::{ED7BA470-8E54-465E-825C-99712043E01C}"
    $appliedCount++

    # 2. KILL UNRESPONSIVE TASKS
    $name = Get-T "KillTasks"
    Write-Host ">> Applying: $name..." -ForegroundColor Gray
    $kill = "$basePath\KillNRTasks"
    Quick-Reg $kill "MUIVerb" $name
    Quick-Reg $kill "Icon" "taskmgr.exe,-30651"
    Quick-Reg "$kill\command" "(Default)" 'CMD.exe /C taskkill.exe /f /fi "status eq Not Responding" & Pause'
    $appliedCount++

    # 3. SAFE MODE
    $name = Get-T "SafeMode"
    Write-Host ">> Applying: $name..." -ForegroundColor Gray
    $sm = "$basePath\SafeMode"
    
    # Pre-clean: Remove the old key to kill any cached bilingual strings
    if (Test-Path $sm) { Remove-Item -Path $sm -Recurse -Force -ErrorAction SilentlyContinue }

    Quick-Reg $sm "MUIVerb" $name
    Quick-Reg $sm "SubCommands" ""
    Quick-Reg $sm "Icon" "bootux.dll,-1032"

    $smItems = @(
        @{ ID="001"; Name=(Get-T "SM_Normal"); CMD="bcdedit /deletevalue {current} safeboot & bcdedit /deletevalue {current} safebootalternateshell"; Icon="shell32.dll,-239" }
        @{ ID="002"; Name=(Get-T "SM_Safe"); CMD="bcdedit /set {current} safeboot minimal & bcdedit /deletevalue {current} safebootalternateshell"; Icon="imageres.dll,-102" }
        @{ ID="003"; Name=(Get-T "SM_Net"); CMD="bcdedit /set {current} safeboot network & bcdedit /deletevalue {current} safebootalternateshell"; Icon="shell32.dll,-257" }
        @{ ID="004"; Name=(Get-T "SM_CMD"); CMD="bcdedit /set {current} safeboot minimal & bcdedit /set {current} safebootalternateshell yes"; Icon="cmd.exe" }
    )

    foreach ($item in $smItems) {
        $path = "$sm\shell\$($item.ID)-Mode"
        
        # Force MUIVerb and kill any existing LocalizedString or CanonicalName that causes bilingual labels
        Quick-Reg $path "MUIVerb" $item.Name
        Quick-Reg $path "(Default)" "" 
        
        # Restore Icon for each sub-item
        if ($item.Icon) { Quick-Reg $path "Icon" $item.Icon }
        
        # Windows 11 26H1 specific: Stop system from fetching default/translated MUI strings
        if (Test-Path $path) {
            Remove-ItemProperty -Path $path -Name "LocalizedString" -ErrorAction SilentlyContinue
            Quick-Reg $path "CanonicalName" "" 
        }

        Quick-Reg "$path\command" "(Default)" "powershell -windowstyle hidden -command `"Start-Process cmd -ArgumentList '/s,/c,$($item.CMD) & shutdown -r -t 00 -f' -Verb runAs`""
    }
    $appliedCount++

    # 4. RESTART EXPLORER
    $name = Get-T "RestartExplorer"
    Write-Host ">> Applying: $name..." -ForegroundColor Gray
    $re = "$basePath\Restart Explorer"

    # Pre-clean to avoid bilingual/ghost issues on Win11 26H1
    if (Test-Path $re) { Remove-Item -Path $re -Recurse -Force -ErrorAction SilentlyContinue }

    Quick-Reg $re "MUIVerb" $name
    Quick-Reg $re "Icon" "explorer.exe"
    Quick-Reg $re "SubCommands" ""

    # Sub-item: Restart Explorer Now
    $pathNow = "$re\shell\01menu"
    Quick-Reg $pathNow "MUIVerb" (Get-T "RE_Now")
    Quick-Reg $pathNow "(Default)" ""
    # ICON: Blue modern Refresh arrows (Fluent style)
    Quick-Reg $pathNow "Icon" "shell32.dll,-16739" 
    Quick-Reg $pathNow "CanonicalName" ""
    Quick-Reg "$pathNow\command" "(Default)" "cmd.exe /c taskkill /f /im explorer.exe & start explorer.exe"

    # Sub-item: Restart Explorer with Pause
    $pathPause = "$re\shell\02menu"
    Quick-Reg $pathPause "MUIVerb" (Get-T "RE_Pause")
    Quick-Reg $pathPause "(Default)" ""
    # ICON: Settings/Process gear with a timer feel
    Quick-Reg $pathPause "Icon" "shell32.dll,-315" 
    Quick-Reg $pathPause "CanonicalName" ""
    Quick-Reg "$pathPause\command" "(Default)" 'cmd.exe /c @echo off & echo Stopping explorer... & taskkill /f /im explorer.exe & pause & start explorer.exe'

    $appliedCount++

    # 5. SYSTEM PROPERTIES
    $name = Get-T "SysProp"
    Write-Host ">> Applying: $name..." -ForegroundColor Gray
    $sp = "$basePath\System Properties"
    Quick-Reg $sp "MUIVerb" $name
    Quick-Reg $sp "Icon" "SystemPropertiesAdvanced.exe"
    Quick-Reg "$sp\command" "(Default)" "SystemPropertiesAdvanced.exe"
    $appliedCount++

    Write-Host "`n[SUCCESS] Context Menu upgrade complete ($langID)." -ForegroundColor Green
    Write-Host "Total Menu Modules: $appliedCount" -ForegroundColor White
}
catch {
    Write-Host "[ERROR] Failed to update context menu: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "--------------------------------------------------------"

##------------------------------------------------------##

# --- Disable CTRL+ALT+DEL Requirement (Registry + SecPol) ---
Write-Host "`n[MODULE] Disabling CTRL+ALT+DEL requirement for logon..." -ForegroundColor Cyan

# 1. Update Registry (Immediate System Effect)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name "DisableCAD" -Value 1 -Type DWord -Force
Write-Host ">> Registry key 'DisableCAD' set to 1." -ForegroundColor Gray

# 2. Update Local Security Policy (SecPol.msc UI Sync)
try {
    $tempFile = "$env:TEMP\secpol_cfg.inf"
    $dbFile = "$env:TEMP\secpol.sdb"

    # Export current security settings to a temporary INF file
    secedit /export /cfg $tempFile /quiet

    # Read the content as a raw string to handle multi-line regex
    $cfgContent = Get-Content $tempFile -Raw
    $cadLine = 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,1'

    # Check if [Registry Values] section exists. If not, append it.
    if ($cfgContent -match "\[Registry Values\]") {
        if ($cfgContent -match "DisableCAD") {
            # Replace any existing value (0 or 1) with the correct one (4,1 -> Enabled/No CAD)
            $cfgContent = $cfgContent -replace "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCAD\s*=\s*\d,\d", $cadLine
        } else {
            # Add the line directly under the section header
            $cfgContent = $cfgContent -replace "\[Registry Values\]", "[Registry Values]`r`n$cadLine"
        }
    } else {
        # Create the entire section if it's missing from the export
        $cfgContent += "`r`n[Registry Values]`r`n$cadLine"
    }

    # Save the modified INF using Unicode encoding (required by secedit)
    $cfgContent | Out-File $tempFile -Encoding Unicode

    # Import and apply the security policy configuration
    secedit /configure /db $dbFile /cfg $tempFile /areas SECURITYPOLICY /quiet
}
catch {
    Write-Host "[ERROR] Failed to sync SecPol.msc: $($_.Exception.Message)" -ForegroundColor Red
}

# --- FINAL VERIFICATION ---
Write-Host ">> Verifying status..." -ForegroundColor Gray
Start-Sleep -Seconds 1 # Short pause for OS processing

$regValue = (Get-ItemProperty -Path $regPath -Name "DisableCAD" -ErrorAction SilentlyContinue).DisableCAD
$checkFile = "$env:TEMP\check.inf"
secedit /export /cfg $checkFile /quiet
$secContent = Get-Content $checkFile -Raw
Remove-Item $checkFile -Force -ErrorAction SilentlyContinue

# Registry Check: 1 = Disabled CAD
if ($regValue -eq 1) {
    Write-Host "[SUCCESS] Registry: CTRL+ALT+DEL is DISABLED." -ForegroundColor Green
} else {
    Write-Host "[FAILED] Registry: Value not applied." -ForegroundColor Red
}

# SecPol UI Check: "4,1" in INF means "Enabled" (Do not require)
if ($secContent -match "DisableCAD=4,1") {
    Write-Host "[SUCCESS] SecPol: UI is now set to 'Enabled' (Do not require)." -ForegroundColor Green
} else {
    Write-Host "[FAILED] SecPol: UI Sync failed." -ForegroundColor Red
}

# Cleanup temporary files
if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
if (Test-Path $dbFile) { Remove-Item $dbFile -Force }

Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# ==============================================================================
# MODULE: PRINT SPOOLER PERMISSIONS REPAIR
# DESCRIPTION: Grants Full Control permissions to the "Everyone" group for the 
#              system spooler directory to resolve access-related print issues.
# ==============================================================================

Write-Host "PRINT SPOOLER PERMISSIONS REPAIR" -ForegroundColor Cyan
Write-Host "[MODULE] Starting Print Spooler Permissions Repair..." -ForegroundColor Cyan
Write-Host "--------------------------------------------------------"

# Define the target spooler printers directory path
$spoolPath = "$env:SystemRoot\System32\spool\PRINTERS"

try {
    Write-Host ">> Granting Full Control to 'Everyone' on: $spoolPath" -ForegroundColor Yellow
    
    # Retrieve current Access Control List (ACL) for the directory
    $acl = Get-Acl $spoolPath
    
    # Use Well-Known SID 'S-1-1-0' (Everyone) to ensure cross-language compatibility
    # This avoids issues between "Everyone" (EN) and "Todos" (PT-BR) localizations.
    $identity = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
    
    # Define Permission Parameters
    $fileSystemRights = "FullControl"
    $inheritanceFlags = "ContainerInherit, ObjectInherit" # Applies to subfolders and files
    $propagationFlags = "None"
    $type             = "Allow"
    
    # Construct the new Access Rule
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity, 
        $fileSystemRights, 
        $inheritanceFlags, 
        $propagationFlags, 
        $type
    )
    
    # Apply the rule to the ACL and commit changes to the file system
    $acl.SetAccessRule($accessRule)
    Set-Acl -Path $spoolPath -AclObject $acl
    
    Write-Host "[OK] Permissions updated successfully." -ForegroundColor Green
} catch {
    # Log failure details for troubleshooting
    Write-Host "[ERROR] Failed to set permissions: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# ==============================================================================
# SCRIPT: Fix Print Spooler Deployment (Smart Language Detection)
# DESCRIPTION: Deploys a silent repair script to C:\Windows and configures 
#               a Desktop Context Menu localized for 22 languages.
# ==============================================================================

Write-Host "FIX PRINT SPOOLER CONTEXT MENU" -ForegroundColor Cyan
Write-Host ""

# --- SERVER CHECK & SPOOLER DISABLE ---
# Verifies if the operating system is a Windows Server variant.
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
if ($osInfo.ProductType -ne 1) { 
    Write-Host "[SERVER DETECTED] System is Windows Server ($($osInfo.Caption))." -ForegroundColor Yellow
    Write-Host "[ACTION] Disabling and stopping Print Spooler for security compliance..." -ForegroundColor Cyan
    
    Set-Service -Name "Spooler" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
    
    Write-Host "[OK] Spooler service disabled. Context menu will NOT be added to Server." -ForegroundColor Green
    Write-Host "--- Process Finished ---" -ForegroundColor Yellow
    return # Exit script here for Server
}

# 1. DEFINE THE CONTENT OF THE SILENT REPAIR SCRIPT (C:\Windows\FixSpooler.ps1)
# This payload is triggered by the context menu to perform the actual repair.
$scriptContent = @'
$spoolPath = "$env:SystemRoot\System32\spool\PRINTERS"

# SERVICE MANAGEMENT: Disable and stop Spooler and PrintNotify services
Set-Service -Name "Spooler" -StartupType Disabled
Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
Stop-Service -Name "PrintNotify" -Force -ErrorAction SilentlyContinue

# QUEUE CLEANUP: Forcefully remove all pending print jobs and metadata
if (Test-Path "$spoolPath\*") {
    try {
        Remove-Item -Path "$spoolPath\*" -Force -Recurse -ErrorAction SilentlyContinue
    } catch {
        # Silent fail on locked files
    }
}

# RESTORATION: Re-enable and start the Spooler service
Set-Service -Name "Spooler" -StartupType Automatic
Start-Service -Name "Spooler"
Exit
'@

# 2. DEPLOY THE PAYLOAD TO THE SYSTEM DIRECTORY
Write-Host "[STEP 1] Deploying repair script to C:\Windows\FixSpooler.ps1..." -ForegroundColor Cyan
try {
    $scriptPath = "C:\Windows\FixSpooler.ps1"
    Set-Content -Path $scriptPath -Value $scriptContent -Force
    Write-Host "[OK] Script payload successfully deployed." -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Critical failure: Unable to write script file to C:\Windows." -ForegroundColor Red
    return
}

# 3. SHELL EXTENSION: CONTEXT MENU REGISTRATION WITH MULTI-LANGUAGE LOGIC
Write-Host "`n[STEP 2] Configuring Desktop Context Menu Registry entries..." -ForegroundColor Cyan

# Detect the current System UI Culture (e.g., pt-BR, en-US)
$currentLang = [System.Globalization.CultureInfo]::CurrentUICulture.Name
Write-Host ">> Environment Language Detected: $currentLang" -ForegroundColor Yellow

# Localization Mapping (22 Languages Supported)
$langMap = @{
    "pt*"    = "Corrigir Spooler de Impressão" # Matches pt-BR, pt-PT
    "en*"    = "Fix Print Spooler"            # Matches all English variants
    "es*"    = "Corregir Cola de impresión"
    "fr*"    = "Réparer le Spouleur d'impression"
    "de*"    = "Druckwarteschlange reparieren"
    "it*"    = "Ripristina Spooler di stampa"
    "ru*"    = "Исправить диспетчер печати"
    "zh-TW*" = "修復列印多多工緩衝處理器"
    "zh-CN*" = "修复打印后台处理程序"
    "ar*"    = "إصلاح Spooler الطباعة"
    "cs*"    = "Opravit službu Spooler"
    "da*"    = "Reparer Print Spooler"
    "nl*"    = "Afdrukspooler repareren"
    "fi*"    = "Korjaa tulostuksen taustatulostus"
    "el*"    = "Επιδιόρθωση ουράς εκτύπωσης"
    "he*"    = "תיקון Print Spooler"
    "hu*"    = "Nyomtatási várólista javítása"
    "ja*"    = "印刷スプーラーを修復する"
    "ko*"    = "인쇄 스풀러 복구"
    "no*"    = "Reparer Print Spooler"
    "pl*"    = "Napraw bufor wydruku"
    "sv*"    = "Reparera Print Spooler"
    "tr*"    = "Yazdırma Biriktiricisi Onar"
}

# Execute Wildcard matching to find the appropriate localized string
$menuName = ""
foreach ($pattern in $langMap.Keys) {
    if ($currentLang -like $pattern) {
        $menuName = $langMap[$pattern]
        break
    }
}

# Fallback mechanism: Default to English if no match is found
if (-not $menuName) { $menuName = "Fix Print Spooler" }

# Define Registry paths and command execution string
$regPath = "Registry::HKEY_LOCAL_MACHINE\Software\Classes\DesktopBackground\Shell\FixSpooler"
$commandPath = "$regPath\command"
# Command launches PowerShell hidden and elevated (RunAs)
$commandValue = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \`"C:\Windows\FixSpooler.ps1\`"' -Verb RunAs`""

try {
    # CRITICAL: Purge existing key to clear MUI cache, legacy values, or conflicting strings
    if (Test-Path $regPath) { 
        Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue 
    }
    
    # Initialize fresh Registry Structure
    New-Item -Path $regPath -Force | Out-Null
    
    # Define UI properties: Localized Name, Icon, and UAC Shield
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $menuName
    Set-ItemProperty -Path $regPath -Name "Icon" -Value "imageres.dll,-51"
    Set-ItemProperty -Path $regPath -Name "HasLUAShield" -Value ""

    # Set the execution command key
    if (-not (Test-Path $commandPath)) { New-Item -Path $commandPath -Force | Out-Null }
    Set-ItemProperty -Path $commandPath -Name "(Default)" -Value $commandValue
    
    Write-Host "[OK] Context menu successfully localized as: '$menuName'" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Registry update failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n--- Deployment Process Finished Successfully ---" -ForegroundColor Yellow
Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

##------------------------------------------------------##

# ==============================================================================
# SCRIPT: Windows Thumbnail & Visual Effects Repair
# DESCRIPTION: Forced cache purge, Registry Policy Fix, and Performance 
#              Options optimization (Thumbnail previews & Desktop shadows).
# ==============================================================================

Write-Host "FIX THUMBNAILS[1/2]" -ForegroundColor Cyan
Write-Host "`n[INIT] Repairing Thumbnail Previews and Visual Effects..." -ForegroundColor Cyan
Write-Host ""

# 1. REGISTRY POLICY: ENFORCE THUMBNAIL ENABLEMENT
# IconsOnly = 0 (Show Thumbnails) | DisableThumbnails = 0 (Enable them)
Write-Host "[PROCESS] Enforcing Thumbnail policies in Registry..." -ForegroundColor Gray
$explorerPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
)

foreach ($path in $explorerPaths) {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "IconsOnly" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $path -Name "DisableThumbnails" -Value 0 -Force -ErrorAction SilentlyContinue
}

# 2. FILE EXTENSIONS: ENSURE THEY ARE VISIBLE
Write-Host "[PROCESS] Showing File Extensions..." -ForegroundColor Gray
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Force

# 3. PERFORMANCE OPTIONS (VISUAL EFFECTS)
# These settings correspond to "System Properties > Performance Options"
Write-Host "[PROCESS] Optimizing Visual Effects (Performance Options)..." -ForegroundColor Gray

$visualEffectsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
if (-not (Test-Path $visualEffectsPath)) { New-Item -Path $visualEffectsPath -Force | Out-Null }

# Set to "Custom" (Value 3) to allow specific flag overrides
Set-ItemProperty -Path $visualEffectsPath -Name "VisualFXSetting" -Value 3 -Force

# FEATURE: "Show thumbnails instead of icons"
# Key: ListviewAlphaSelect (Value 1 enables this effect)
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 1 -Force -ErrorAction SilentlyContinue

# FEATURE: "Use drop shadows for icon labels on the desktop"
# Key: ListviewShadow (Value 1 enables)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Value 1 -Force

# 4. SYSTEM-WIDE REFRESH
# This forces the Shell to update its state without a full logout
Write-Host "[PROCESS] Refreshing Shell State..." -ForegroundColor Gray
$updateCode = @'
[System.Runtime.InteropServices.DllImport("shell32.dll")]
public static extern void SHChangeNotify(int wEventId, int uFlags, IntPtr dwItem1, IntPtr dwItem2);
'@
Add-Type -MemberDefinition $updateCode -Namespace WinAPI -Name Shell32
[WinAPI.Shell32]::SHChangeNotify(0x08000000, 0x0000, [IntPtr]::Zero, [IntPtr]::Zero)

Write-Host "[SUCCESS] Thumbnail repair and visual effects applied." -ForegroundColor Green
Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

##------------------------------------------------------##

# --- Take Ownership Context Menu (Universal Native Method) ---
# Description: Deploys a high-privilege "Take Ownership" context menu for Files and Directories.
# Method: Generates a temporary UTF-16LE .reg file to bypass Registry locks and character conflicts.
# Target: Windows 10/11 (Global Support - 22 Languages)

# 1. Administrator Privilege Enforcement
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Elevated privileges required. Please run this script as Administrator."
    exit
}

# 2. Global Language Dictionary (22 Languages)
$langID = (Get-Culture).TwoLetterISOLanguageName
$t = @{
    "TakeOwnership" = @{ 
        "en"="Take Ownership"; "pt"="Obter Controle Total"; "es"="Tomar posesión"; "de"="Besitz übernehmen"; 
        "nl"="Eigenaar worden"; "fr"="Prendre possession"; "it"="Diventa proprietario"; "ja"="所有権の取得"; 
        "ko"="소유권 가져오기"; "zh"="取得所有权"; "uk"="Стати власником"; "ru"="Стать владельцем"; 
        "bg"="Стани собственик"; "hi"="स्वामित्व लें"; "tr"="Sahipliği Al"; "vi"="Chiếm quyền sở hữu"; 
        "th"="เป็นเจ้าของ"; "id"="Ambil Kepemilikan"; "ms"="Ambil Pemilikan"; "fi"="Ota omistajuus"; 
        "he"="קבל בעלות"; "el"="Ανάληψη κυριότητας" 
    }
}

$localizedName = if ($t["TakeOwnership"][$langID]) { $t["TakeOwnership"][$langID] } else { $t["TakeOwnership"]["en"] }

Write-Host "[PROCESS] Deploying '$localizedName' with custom Checkmark Icon..." -ForegroundColor Cyan

# 3. Registry Payload Generation (Here-String)
# The "Icon" value uses shell32.dll,-253 to display the orange checkmark.
$regContent = @"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\runas]
@="$localizedName"
"Icon"="shell32.dll,-253"
"HasLUAShield"=""
"NoWorkingDirectory"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\runas\command]
@="cmd.exe /c takeown /f \"%1\" & icacls \"%1\" /grant *S-1-5-32-544:F & Pause"
"IsolatedCommand"="cmd.exe /c takeown /f \"%1\" & icacls \"%1\" /grant *S-1-5-32-544:F & Pause"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\runas]
@="$localizedName"
"Icon"="shell32.dll,-253"
"HasLUAShield"=""
"NoWorkingDirectory"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\runas\command]
@="cmd.exe /c takeown /f \"%1\" /r /d y & icacls \"%1\" /grant *S-1-5-32-544:F /t /c /l & Pause"
"IsolatedCommand"="cmd.exe /c takeown /f \"%1\" /r /d y & icacls \"%1\" /grant *S-1-5-32-544:F /t /c /l & Pause"
"@

try {
    # 4. File I/O & Deployment
    $tempReg = "$env:TEMP\take_ownership_deploy.reg"
    $regContent | Out-File -FilePath $tempReg -Encoding Unicode -Force

    # Executing the import via reg.exe
    Start-Process "reg.exe" -ArgumentList "import `"$tempReg`"" -Wait -NoNewWindow

    # 5. Post-Deployment Cleanup
    Remove-Item $tempReg -Force -ErrorAction SilentlyContinue

    Write-Host "[SUCCESS] '$localizedName' integrated into context menu successfully!!" -ForegroundColor Green
}
catch {
    Write-Host "[CRITICAL ERROR] Failed to finalize registry deployment: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

##------------------------------------------------------##

# --- MSCONFIG: UNCHECK NUMBER OF PROCESSORS ---
Write-Host "[MODULE] Checking MSConfig Advanced Boot Options..." -ForegroundColor Cyan

try {
    # 1. GET REAL BOOT ID (Prevents "Invalid Parameter" errors)
    $bootId = bcdedit /get "{current}" device 2>$null
    if ($null -eq $bootId) { $target = "{default}" } else { $target = "{current}" }

    # 2. REAL CHECK (Verifies if 'numproc' value exists)
    $bcdData = bcdedit /enum $target
    if ($bcdData -match "numproc") {
        Write-Host "!! ATTENTION: 'Number of Processors' is CHECKED in the system !!" -ForegroundColor Red
        
        # PROCEDURE A: Remove BCD lock using the correct ID
        Write-Host "-> PROCEDURE A: Deleting CPU core limit from BCD..." -ForegroundColor Yellow
        bcdedit /deletevalue $target numproc 2>$null
        
        # PROCEDURE B: Reset interface flags in Registry (Clears the UI "V" mark)
        Write-Host "-> PROCEDURE B: Clearing MSConfig visual cache..." -ForegroundColor Yellow
        $regPath = "HKLM:\SOFTWARE\Microsoft\Shared Tools\MSConfig\state"
        if (Test-Path $regPath) {
            Set-ItemProperty -Path $regPath -Name "allbootmsconfi" -Value 0 -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $regPath -Name "flags" -Value 0 -Force -ErrorAction SilentlyContinue
        }

        # PROCEDURE C: Clear environment variables forcing core counts
        Write-Host "-> PROCEDURE C: Removing hardware overrides..." -ForegroundColor Yellow
        $envPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        Remove-ItemProperty -Path $envPath -Name "NUMBER_OF_PROCESSORS" -ErrorAction SilentlyContinue

        Write-Host "`n[SUCCESS] Procedures finalized." -ForegroundColor Green
        Write-Host "CLOSE and OPEN MSConfig. The box SHOULD be unchecked now." -ForegroundColor Cyan
    } 
    else {
        Write-Host "[OK] 'Number of Processors' is already unchecked." -ForegroundColor Gray
    }
} 
catch {
    Write-Host "[ERROR] Failed to access boot configuration data." -ForegroundColor Red
}

Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

<#
    Workstation Optimization & Setup Script
    Organization: Registry Tweaks, System Performance
#>

Write-Host "Starting System Configuration..." -ForegroundColor Cyan

# --- 1. System Performance: Automatic Pagefile Management ---
Write-Host "Setting system-managed pagefile..."
Set-CimInstance -Query "Select * from Win32_ComputerSystem" -Property @{AutomaticManagedPagefile=$True}

# --- 2. Network Optimization: Fix CFG & Remove QoS Bandwidth Limit ---
Write-Host "Configuring Network QoS Limits..."
Set-ExecutionPolicy Bypass -Scope Process -Force; 
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Force }
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Value 0 -PropertyType DWord -Force

# --- 3. Explorer: Hide Recycle Bin from Desktop ---
Write-Host "Hiding Recycle Bin from Desktop..." -ForegroundColor Cyan

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$binGuid = "{645FF040-5081-101B-9F08-00AA002F954E}"

# Ensure the registry key (folder) exists before creating the value
if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the value to hide the icon (1 = Hidden, 0 = Visible)
# Set-ItemProperty is used here because it creates the value if it doesn't exist 
# or updates it if it does, preventing the "path not found" error.
Set-ItemProperty -Path $regPath -Name $binGuid -Value 1 -Type DWord -Force

Write-Host "Recycle Bin hidden successfully! ✅" -ForegroundColor Green

# --- 4. Explorer: Pin Recycle Bin to Navigation Pane ---
Write-Host "Pinning Recycle Bin to Explorer Sidebar..."
if (!(Test-Path "HKCU:\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}")) { New-Item -Path "HKCU:\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" -Force }
New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" -Name "System.IsPinnedToNameSpaceTree" -Value 1 -PropertyType DWord -Force

# --- 5. Graphics: Disable Wallpaper JPEG Compression ---
Write-Host "Setting Wallpaper quality to 100%..."
if (!(Test-Path "HKCU:\Control Panel\Desktop")) { New-Item -Path "HKCU:\Control Panel\Desktop" -Force }
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Value 100 -PropertyType DWord -Force

# --- 6. Security/Login: Enable NumLock on Login Screen ---
Write-Host "Enabling NumLock on Login Screen..."
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Value "2147483650"

# --- 7. Context Menu: Restore 'New Text Document' ---
Write-Host "Restoring 'New Text Document' to Context Menu..."
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue
New-Item -Path 'HKCR:\.rtf\ShellNew','HKCR:\.txt\PersistentHandler','HKCR:\.txt\ShellNew','HKCR:\SystemFileAssociations\.txt','HKCR:\txtfile\DefaultIcon','HKCR:\txtfile\shell\open\command','HKCR:\txtfile\shell\print\command','HKCR:\txtfile\shell\printto\command' -Force | Out-Null
Set-ItemProperty -Path 'HKCR:\.rtf\ShellNew' -Name 'NullFile' -Value ''
Set-Item -Path 'HKCR:\.txt' -Value 'txtfile'
Set-ItemProperty -Path 'HKCR:\.txt' -Name 'Content Type' -Value 'text/plain'
Set-ItemProperty -Path 'HKCR:\.txt' -Name 'PerceivedType' -Value 'text'
Set-Item -Path 'HKCR:\.txt\PersistentHandler' -Value '{5e941d80-bf96-11cd-b579-08002b30bfeb}'
Set-ItemProperty -Path 'HKCR:\.txt\ShellNew' -Name 'NullFile' -Value ''
Set-ItemProperty -Path 'HKCR:\.txt\ShellNew' -Name 'ItemName' -Value '@%SystemRoot%\system32\notepad.exe,-470'
Set-ItemProperty -Path 'HKCR:\SystemFileAssociations\.txt' -Name 'PerceivedType' -Value 'document'
Set-Item -Path 'HKCR:\txtfile' -Value 'Text Document'
Set-ItemProperty -Path 'HKCR:\txtfile' -Name 'EditFlags' -Value 2162688
Set-ItemProperty -Path 'HKCR:\txtfile' -Name 'FriendlyTypeName' -Value '@%SystemRoot%\system32\notepad.exe,-469'
Set-Item -Path 'HKCR:\txtfile\DefaultIcon' -Value '%SystemRoot%\system32\imageres.dll,-102'
Set-Item -Path 'HKCR:\txtfile\shell\open\command' -Value '%SystemRoot%\system32\NOTEPAD.EXE %1'

# --- 8. Updates: Disable Automatic Driver Updates ---
Write-Host "Disabling Automatic Driver Updates..."
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ExcludeWUDriversInQualityUpdate' -Value 1 -Type DWord
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' -Name 'SearchOrderConfig' -Value 0

# --- 9. Updates: Disable Malicious Software Removal Tool (MRT) via WU ---
Write-Host "Disabling MRT Offers..."
if(!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\MRT')){ New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' -Force | Out-Null }
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' -Name 'DontOfferThroughWUAU' -Value 1 -Type DWord

# --- 10. Context Menu: Restore "New" Menu for Scripting Extensions (Multi-Language) ---
Write-Host "`n[MODULE] Restoring 'New File' Context Menu for Scripting Extensions..." -ForegroundColor Cyan

# Detect system language
$langID = (Get-Culture).TwoLetterISOLanguageName

# Multi-language dictionary for ShellNew Item Names
$translations = @{
    ".vbs" = @{ "en"="VBScript"; "pt"="VBScript"; "es"="VBScript"; "de"="VBScript"; "nl"="VBScript"; "fr"="VBScript"; "it"="VBScript"; "ja"="VBScript"; "ko"="VBScript"; "zh"="VBScript"; "uk"="VBScript"; "ru"="VBScript"; "bg"="VBScript"; "hi"="VBScript"; "tr"="VBScript"; "vi"="VBScript"; "th"="VBScript"; "id"="VBScript"; "ms"="VBScript"; "fi"="VBScript"; "he"="VBScript"; "el"="VBScript" }
    ".bat" = @{ "en"="Batch File (.bat)"; "pt"="Arquivo de Lote (.bat)"; "es"="Archivo por lotes (.bat)"; "de"="Stapelverarbeitungsdatei (.bat)"; "nl"="Batchbestand (.bat)"; "fr"="Fichier de commandes (.bat)"; "it"="File batch (.bat)"; "ja"="バッチファイル (.bat)"; "ko"="배치 파일 (.bat)"; "zh"="批处理文件 (.bat)"; "uk"="Пакетний файл (.bat)"; "ru"="Пакетный файл (.bat)"; "bg"="Пакетен файл (.bat)"; "hi"="बैच फ़ाइल (.bat)"; "tr"="Toplu İş Dosyası (.bat)"; "vi"="Tệp lô (.bat)"; "th"="ไฟล์แบตช์ (.bat)"; "id"="File batch (.bat)"; "ms"="Fail kelompok (.bat)"; "fi"="Eräajo-tiedosto (.bat)"; "he"="קובץ Batch (.bat)"; "el"="Αρχείο δέσμης ενεργειών (.bat)" }
    ".cmd" = @{ "en"="Command Script (.cmd)"; "pt"="Script de Comando (.cmd)"; "es"="Script de comando (.cmd)"; "de"="Befehlsskript (.cmd)"; "nl"="Opdrachtscript (.cmd)"; "fr"="Script de commande (.cmd)"; "it"="Script di comando (.cmd)"; "ja"="コマンドスクリプト (.cmd)"; "ko"="명령 스크립트 (.cmd)"; "zh"="命令脚本 (.cmd)"; "uk"="Командний сценарій (.cmd)"; "ru"="Командный сценарий (.cmd)"; "bg"="Команден скрипт (.cmd)"; "hi"="कमांड स्क्रिप्ट (.cmd)"; "tr"="Komut Dosyası (.cmd)"; "vi"="Kịch bản lệnh (.cmd)"; "th"="สคริปต์คำสั่ง (.cmd)"; "id"="Skrip perintah (.cmd)"; "ms"="Skrip arahan (.cmd)"; "fi"="Komentosarjassa (.cmd)"; "he"="סקריפט פקודה (.cmd)"; "el"="Δέσμη εντολών (.cmd)" }
    ".reg" = @{ "en"="Registry Entries (.reg)"; "pt"="Entradas de Registro (.reg)"; "es"="Entradas de registro (.reg)"; "de"="Registrierungseinträge (.reg)"; "nl"="Registervermeldingen (.reg)"; "fr"="Entrées de registre (.reg)"; "it"="Voci di registro (.reg)"; "ja"="レジストリエントリ (.reg)"; "ko"="레ジ스트리 항목 (.reg)"; "zh"="注册表项 (.reg)"; "uk"="Записи реєстру (.uk)"; "ru"="Записи реестра (.reg)"; "bg"="Записи в регистъра (.reg)"; "hi"="रजिस्ट्री प्रविष्टियाँ (.reg)"; "tr"="Kayıt Defteri Girdileri (.reg)"; "vi"="Mục đăng ký (.reg)"; "th"="รายการรีจิสทรี (.reg)"; "id"="Entri registri (.reg)"; "ms"="Kemasukan pendaftaran (.reg)"; "fi"="Rekisterimerkinnät (.reg)"; "he"="ערכי רישום (.reg)"; "el"="Καταχωρήσεις μητρώου (.reg)" }
    ".ps1" = @{ "en"="PowerShell Script (.ps1)"; "pt"="Script do PowerShell (.ps1)"; "es"="Script de PowerShell (.ps1)"; "de"="PowerShell-Skript (.ps1)"; "nl"="PowerShell-script (.ps1)"; "fr"="Script PowerShell (.ps1)"; "it"="Script PowerShell (.ps1)"; "ja"="PowerShell スクリプト (.ps1)"; "ko"="PowerShell 스크립트 (.ps1)"; "zh"="PowerShell 脚本 (.ps1)"; "uk"="Сценарій PowerShell (.ps1)"; "ru"="Сценарий PowerShell (.ps1)"; "bg"="PowerShell скрипт (.ps1)"; "hi"="PowerShell स्क्रिप्ट (.ps1)"; "tr"="PowerShell Betiği (.ps1)"; "vi"="Kịch bản PowerShell (.ps1)"; "th"="สคริปต์ PowerShell (.ps1)"; "id"="Skrip PowerShell (.ps1)"; "ms"="Skrip PowerShell (.ps1)"; "fi"="PowerShell-skripti (.ps1)"; "he"="סקריפט PowerShell (.ps1)"; "el"="Δέσμη ενεργειών PowerShell (.ps1)" }
}

$shellNewItems = @(
    @{ Ext = ".vbs"; Progid = "VBSFile" }
    @{ Ext = ".bat"; Progid = "batfile" }
    @{ Ext = ".cmd"; Progid = "cmdfile" }
    @{ Ext = ".reg"; Progid = "regfile" }
    @{ Ext = ".ps1"; Progid = "Microsoft.PowerShellScript.1" }
)

foreach ($item in $shellNewItems) {
    try {
        # Select the translated name based on detected language, fallback to English
        $ext = $item.Ext
        $customName = if ($translations[$ext].ContainsKey($langID)) { $translations[$ext][$langID] } else { $translations[$ext]["en"] }

        # 1. Cache and UserChoice Cleanup
        $userChoicePath = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext\UserChoice"
        if (Test-Path $userChoicePath) { 
            Remove-Item -Path $userChoicePath -Force -Recurse -ErrorAction SilentlyContinue 
        }

        $cachePath = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Discardable\PostSetup\ShellNew"
        if (Test-Path $cachePath) { 
            Remove-Item -Path $cachePath -Force -ErrorAction SilentlyContinue 
        }

        # 2. Assign Friendly Name to Progid
        $progidPath = "Registry::HKEY_CLASSES_ROOT\$($item.Progid)"
        if (Test-Path $progidPath) {
            Set-ItemProperty -Path $progidPath -Name "(Default)" -Value $customName -Force
            Remove-ItemProperty -Path $progidPath -Name "FriendlyTypeName" -ErrorAction SilentlyContinue
        }

        # 3. Rebuild ShellNew Structure
        $regPaths = @(
            "Registry::HKEY_CLASSES_ROOT\$ext",
            "Registry::HKEY_CURRENT_USER\Software\Classes\$ext"
        )

        foreach ($path in $regPaths) {
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
            Set-ItemProperty -Path $path -Name "(Default)" -Value $item.Progid -Force
            
            $sn = "$path\ShellNew"
            if (-not (Test-Path $sn)) { New-Item -Path $sn -Force | Out-Null }
            
            Set-ItemProperty -Path $sn -Name "NullFile" -Value "" -Force
            Set-ItemProperty -Path $sn -Name "MenuText" -Value $customName -Force
            Set-ItemProperty -Path $sn -Name "ItemName" -Value $customName -Force
        }
        Write-Host "[SUCCESS] 'New' item restored for: $ext ($langID)" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to restore $($item.Ext): $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "--------------------------------------------------------"
Write-Host "Context Menu restoration complete!" -ForegroundColor Yellow
Write-Host ""

# --- 11. Service Host Grouping Optimization (SvcHostSplitThreshold) ---
# This adjusts how Windows groups services into svchost.exe processes.
# The logic follows the Winaero methodology: Total RAM + 1024000 KB margin.
Write-Host "-- Optimizing SvcHost Split Threshold based on RAM..." -ForegroundColor Gray

try {
    # Get total physical RAM in KB
    $totalRAMkb = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1024
    
    # Calculate the threshold with the Winaero margin
    $thresholdValue = [math]::Floor($totalRAMkb + 1024000)

    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control"
    
    # Apply the calculated value to the Registry
    Set-ItemProperty -Path $registryPath -Name "SvcHostSplitThresholdInKB" -Value $thresholdValue -Type DWord -Force
    
    Write-Host "SvcHost threshold dynamically set to: $thresholdValue KB ✅" -ForegroundColor Green
} catch {
    Write-Warning "Failed to calculate or set SvcHost threshold."
}

# --- 12. Disable Background Apps Globally ---
# This prevents UWP/Store apps from running in the background, 
# saving CPU cycles and RAM.
Write-Host "-- Disabling Background Apps globally..." -ForegroundColor Gray
$bgAppPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"

try {
    if (!(Test-Path $bgAppPath)) { 
        New-Item -Path $bgAppPath -Force | Out-Null 
    }
    Set-ItemProperty -Path $bgAppPath -Name "GlobalUserDisabled" -Value 1 -Type DWord -Force
    Write-Host "Background apps disabled successfully! ✅" -ForegroundColor Green
} catch {
    Write-Warning "Failed to disable background apps."
}

# --- 13. Long-term Windows Update Pause (Year 3000) ---
# This forces Windows Update to stay paused until the year 3000.
Write-Host "-- Hard-pausing Windows Updates until year 3000..." -ForegroundColor Gray
$wuPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"

try {
    if (!(Test-Path $wuPath)) { 
        New-Item -Path $wuPath -Force | Out-Null 
    }

    $updateValues = @{
        "PauseFeatureUpdatesStartTime" = "2022-09-30T10:23:59Z"
        "PauseFeatureUpdatesEndTime"   = "3000-12-31T10:23:59Z"
        "PauseQualityUpdatesStartTime" = "2022-09-30T10:23:59Z"
        "PauseQualityUpdatesEndTime"   = "3000-12-31T10:23:59Z"
        "PauseUpdatesStartTime"        = "2022-09-30T10:23:59Z"
        "PauseUpdatesExpiryTime"       = "3000-12-31T10:23:59Z"
    }

    foreach ($name in $updateValues.Keys) {
        Set-ItemProperty -Path $wuPath -Name $name -Value $updateValues[$name] -Type String -Force
    }
    
    Write-Host "Windows Updates paused until year 3000! ✅" -ForegroundColor Green
} catch {
    Write-Warning "Failed to pause Windows Updates."
}

# --- 14. Context Menu: Add 'Check File Ownership' (High-Speed Native Deployment) ---
Write-Host "`n[MODULE] Configuring 'Check Owner' Context Menu (Fast Mode)..." -ForegroundColor Cyan

# Get the ReleaseId or DisplayVersion
$regPathNT = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$releaseVersion = (Get-ItemProperty -Path $regPathNT -Name "DisplayVersion").DisplayVersion

# Apply configuration ONLY if version is NOT "25H2" (Targeting 26H1+)
if ($releaseVersion -ne "25H2") {
    
    # Define the command string carefully for reg.exe escaping
    $cmdValue = 'powershell.exe -NoExit -Command \"$owner = (Get-ChildItem ''%1'' -Force).GetAccessControl().Owner; Write-Host \"\"Owner : $owner\"\"\"'
    
    # List of keys to create/update
    $ownerKeys = @(
        'HKEY_CURRENT_USER\Software\Classes\*\shell\Owner\command',
        'HKEY_CURRENT_USER\Software\Classes\Directory\shell\Owner\command',
        'HKEY_CURRENT_USER\Software\Classes\Drive\shell\Owner\command'
    )

    foreach ($key in $ownerKeys) {
        # Using reg add: /ve (default value), /t REG_SZ (type), /f (force/overwrite)
        # We use Start-Process with cmd /c to ensure zero-lag execution and background handling
        Start-Process cmd -ArgumentList "/c reg add `"$key`" /ve /t REG_SZ /d `"$cmdValue`" /f >nul 2>&1" -WindowStyle Hidden -Wait
        Write-Host "." -NoNewline -ForegroundColor Gray
    }

    Write-Host "`n[SUCCESS] 'Owner' check configured via reg.exe. ✅" -ForegroundColor Green
} else {
    Write-Host "Detected version $releaseVersion. Skipping configuration (Only for 26H1+). ⏩" -ForegroundColor Yellow
}

Write-Host ""

# --- 15. Disable Network Access in Modern Standby ---
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"

# Ensure the registry key exists
if (!(Test-Path $regPath)) {
    [void](New-Item -Path $regPath -Force)
}

# Use the .NET Registry class to bypass PowerShell cmdlet parameter issues
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9", $true)
if ($key) {
    $key.SetValue("ACSettingIndex", 0, [Microsoft.Win32.RegistryValueKind]::DWord)
    $key.Close()
}

Write-Host "Modern Standby network connectivity setting has been applied." -ForegroundColor Green
Write-Host ""

# 16. Show all browser tabs in Alt+Tab (Set to 0 to show open windows only, or 20 tabs)
Write-Host "-- Configuring Alt+Tab to show all tabs..." -ForegroundColor Gray
$altTabPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Set-ItemProperty -Path $altTabPath -Name "MultiTaskingAltTabFilter" -Value 0 -Type DWord
Write-Host ""

# 17. Launch File Explorer to 'This PC' instead of 'Home/Quick Access'
Write-Host "-- Setting Explorer to launch to 'This PC'..." -ForegroundColor Gray
Set-ItemProperty -Path $altTabPath -Name "LaunchTo" -Value 1 -Type DWord
Write-Host ""

# 18. Increase Right-Click limit (MultipleInvokePromptMinimum) to 128 items
Write-Host "-- Increasing context menu limit for multiple files..." -ForegroundColor Gray
$explorerLimitPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer"
if (!(Test-Path $explorerLimitPath)) { New-Item -Path $explorerLimitPath -Force | Out-Null }
Set-ItemProperty -Path $explorerLimitPath -Name "MultipleInvokePromptMinimum" -Value 129 -Type DWord
Write-Host ""

# 19. Prevent automatic restarts after updates while signed in
Write-Host "-- Preventing auto-reboot after Windows Updates..." -ForegroundColor Gray
$auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
if (!(Test-Path $auPath)) { New-Item -Path $auPath -Force | Out-Null }
Set-ItemProperty -Path $auPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord
Write-Host ""

# 20. Add all User Folders (Desktop, Music, etc.) under 'This PC' in Explorer
Write-Host "-- Adding user folders under 'This PC'..." -ForegroundColor Gray
$namespacePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"
$folders = @(
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", # Desktop
    "{d3162b92-9365-467a-956b-92703aca08af}", # Documents
    "{088e3905-0323-4b02-9826-5d99428e115f}", # Downloads
    "{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}", # Music
    "{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"  # Pictures
)

foreach ($guid in $folders) {
    $path = Join-Path $namespacePath $guid
    if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    
    # Remove the block (equivalent to "HideIfEnabled"=-)
    Remove-ItemProperty -Path $path -Name "HideIfEnabled" -ErrorAction SilentlyContinue
    
    # Set as visible
    Set-ItemProperty -Path $path -Name "HiddenByDefault" -Value 0 -Type DWord
}

Write-Host ""
Write-Host "Registry tweaks applied successfully! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

# 21. Browser Tweaks: Chrome, Brave, Edge & Firefox
Write-Host "-- Applying Browser Registry Tweaks (Chrome, Brave, Edge & Firefox)..." -ForegroundColor Gray

# List of registry paths for centralized policy management
$browserPaths = @(
    "HKLM:\SOFTWARE\Policies\Google\Chrome",
    "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
    "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
    "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
)

# Shared Policy Settings (Applies to most Chromium-based browsers and Firefox)
$sharedTweaks = @{
    "PasswordManagerEnabled"          = 1   # Keep "Offer to save passwords" active
    "MetricsReportingEnabled"         = 0   # Disable Telemetry and usage data collection
    "BackgroundModeEnabled"           = 0   # Prevent browser from running in the background after closing
    "HardwareAccelerationModeEnabled" = 0   # Disable GPU acceleration (useful for troubleshooting/stability)
    "ComponentUpdatesEnabled"         = 0   # Disable automatic internal component updates
    "BuiltInComponentUpdaterEnabled"  = 0   # Disable built-in cleanup and reporting tools
    "NetworkPredictionOptions"        = 2   # Disable DNS pre-fetching / Page prediction
    "SpellcheckEnabled"               = 0   # Disable built-in spellchecking service
}

foreach ($basePath in $browserPaths) {
    # Create the key if it does not exist
    if (!(Test-Path $basePath)) { New-Item -Path $basePath -Force | Out-Null }
    
    # Determine the correct registry type (Firefox requires String for these policies)
    $type = if ($basePath -like "*Mozilla*") { "String" } else { "DWord" }
    
    foreach ($name in $sharedTweaks.Keys) {
        Set-ItemProperty -Path $basePath -Name $name -Value $sharedTweaks[$name] -Type $type -ErrorAction SilentlyContinue
    }
}

# --- FIREFOX SPECIFIC DEBLOAT ---
# Policies specifically for Mozilla Firefox's engine
$firefoxOnlyPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
$firefoxTweaks = @{
    "DisableTelemetry"           = "1"  # Disable all telemetry reports
    "DisableFirefoxStudies"      = "1"  # Prevent Mozilla from running SHIELD studies
    "DisablePocket"              = "1"  # Remove the Pocket integration from the UI
    "DisableAppUpdate"           = "1"  # Stop Firefox from updating automatically
    "OverrideFirstRunPage"       = ""   # Skip the "Welcome" tab on new profiles
    "OverridePostUpdatePage"     = ""   # Skip the "What's New" tab after updates
    "DisableFirefoxScreenshots"  = "0"  # Keep screenshot tool enabled (useful utility)
    "DisableFirefoxAccounts"     = "0"  # Keep Firefox Sync enabled
    "DisableFeedbackCommands"    = "1"  # Remove "Submit Feedback" from menus
    "DisableDefaultBrowserAgent" = "1"  # Disable the service that checks if Firefox is default
    "DisableImportResources"     = "1"  # Disable prompts to import data from other browsers
}

foreach ($name in $firefoxTweaks.Keys) {
    Set-ItemProperty -Path $firefoxOnlyPath -Name $name -Value $firefoxTweaks[$name] -Type String -ErrorAction SilentlyContinue
}

# --- BRAVE SPECIFIC DEBLOAT ---
# Policies for Brave-specific features (Web3, Rewards, and AI)
$braveOnlyPath = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
$braveTweaks = @{
    "BraveVPNDisabled"     = 1  # Remove Brave VPN button and service
    "BraveWalletDisabled"  = 1  # Disable the built-in Crypto Wallet
    "BraveAIChatEnabled"   = 0  # Disable "Leo" AI Chat
    "BraveRewardsDisabled" = 1  # Disable Brave Rewards/Ads
    "BraveTalkDisabled"    = 1  # Disable the "Brave Talk" video call feature
    "BraveNewsDisabled"    = 1  # Disable the Brave News feed on new tabs
}

foreach ($name in $braveTweaks.Keys) {
    Set-ItemProperty -Path $braveOnlyPath -Name $name -Value $braveTweaks[$name] -Type DWord -ErrorAction SilentlyContinue
}

# --- MICROSOFT EDGE SPECIFIC DEBLOAT ---
# Extensive cleanup of Edge's tracking, shopping, and sidebar features
$edgeOnlyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$edgeTweaks = @{
    "EdgeEnhanceImagesEnabled"         = 0  # Disable image super-resolution
    "PersonalizationReportingEnabled"  = 0  # Disable personalization telemetry
    "ShowRecommendationsEnabled"       = 0  # Remove recommendations from the UI
    "HideFirstRunExperience"           = 1  # Skip the massive "First Run" setup
    "UserFeedbackAllowed"              = 0  # Disable "Send Feedback"
    "ConfigureDoNotTrack"              = 1  # Enable "Do Not Track" header
    "AlternateErrorPagesEnabled"       = 0  # Disable Microsoft's error pages
    "EdgeCollectionsEnabled"           = 0  # Disable the "Collections" feature
    "EdgeFollowEnabled"                = 0  # Disable the "Follow Creator" feature
    "EdgeShoppingAssistantEnabled"     = 0  # Disable shopping/coupons popups
    "MicrosoftEdgeInsiderPromotionEnabled" = 0 # Disable Insider promotions
    "RelatedMatchesCloudServiceEnabled" = 0 # Disable cloud-based related searches
    "ShowMicrosoftRewards"             = 0  # Remove Rewards icon
    "WebWidgetAllowed"                 = 0  # Disable the Edge "Desktop Widget"
    "StartupBoostEnabled"              = 0  # Stop Edge from launching at Windows startup
    "BingAdsSuppression"               = 0  # Suppress Bing search ads
    "NewTabPageHideDefaultTopSites"    = 0  # Cleanup default sites on new tabs
    "PromotionalTabsEnabled"           = 0  # Disable "Promotional" popups
    "SendSiteInfoToImproveServices"    = 0  # Disable site tracking for "improvement"
    "SpotlightExperiencesAndRecommendationsEnabled" = 0 # Disable spotlight ads
    "DiagnosticData"                   = 0  # Set diagnostic data to minimal/off
    "EdgeAssetDeliveryServiceEnabled"  = 0  # Disable asset background delivery
    "CryptoWalletEnabled"              = 0  # Disable Edge Crypto Wallet
    "WalletDonationEnabled"            = 0  # Disable donation features in Wallet
    "HubsSidebarEnabled"               = 0  # Remove the Edge Sidebar
    "CopilotPageAction"                = 0  # Disable the Copilot icon/action
}

foreach ($name in $edgeTweaks.Keys) {
    Set-ItemProperty -Path $edgeOnlyPath -Name $name -Value $edgeTweaks[$name] -Type DWord -ErrorAction SilentlyContinue
}

# --- DNS CACHE OPTIMIZATION ---
# Increases the efficiency of the local Windows DNS cache for faster page loads
$dnsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
if (Test-Path $dnsPath) {
    Set-ItemProperty -Path $dnsPath -Name "CacheHashTableBucketSize" -Value 1 -Type DWord
    Set-ItemProperty -Path $dnsPath -Name "CacheHashTableSize" -Value 384 -Type DWord
    Set-ItemProperty -Path $dnsPath -Name "MaxCacheEntryTtlLimit" -Value 10800 -Type DWord # 3 hours
    Set-ItemProperty -Path $dnsPath -Name "MaxSOACacheEntryTtlLimit" -Value 301 -Type DWord
}

Write-Host "Browser tweaks applied successfully! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

# --- 22. USER SECURITY (PASSWORD NEVER EXPIRES) ---
Write-Host "Updating password expiration policy for user: Admin..." -ForegroundColor Cyan

try {
    # Check if the user exists first
    if (Get-LocalUser -Name "Admin" -ErrorAction SilentlyContinue) {
        # Target the specific account and apply the 'Never Expires' flag
        # -ErrorAction Stop forces the command to jump to 'catch' if it fails
        Set-LocalUser -Name "Admin" -PasswordNeverExpires $true -ErrorAction Stop
        Write-Host "[Admin] Status changed to PASSWORD NEVER EXPIRES successfully." -ForegroundColor Green
    }
    else {
        Write-Host "[WARNING] User 'Admin' not found on this system. Skipping..." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "[ERROR] Failed to update user 'Admin'. Ensure the script is running with Administrative privileges." -ForegroundColor Red
}

Write-Host "--------------------------------------------------------"

# --- 23. ENABLE DETAILED BSOD ---
Write-Host "Enabling Detailed Blue Screen of Death (BSOD) information..." -ForegroundColor Cyan
try {
    $bsodPath = "HKLM:\System\CurrentControlSet\Control\CrashControl"
    if (-not (Test-Path $bsodPath)) { New-Item -Path $bsodPath -Force | Out-Null }
    Set-ItemProperty -Path $bsodPath -Name "DisplayParameters" -Value 1 -Type DWord -Force
    Write-Host "[SUCCESS] Detailed BSOD information enabled." -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Failed to set Detailed BSOD parameters." -ForegroundColor Red
}

Write-Host ""

##------------------------------------------------------##

# --- Performance and Telemetry Optimizations ---
Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Applying System and Office optimizations..." -ForegroundColor Cyan

# 1. Mouse and UI Responsiveness
Write-Host "-- Disabling Mouse Delay and Acceleration..." -ForegroundColor Gray
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "0" -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Value "0" -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value "0" -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value "0" -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value "0" -Force

# 2. System Services (Prefetch/SysMain)
Write-Host "-- Disabling SysMain (Prefetch)..." -ForegroundColor Gray
Stop-Service -Name "sysmain" -ErrorAction SilentlyContinue
Set-Service -Name "sysmain" -StartupType Disabled

# 3. Telemetry (PowerShell & Office)
Write-Host "-- Disabling PowerShell and Office telemetry..." -ForegroundColor Gray
# PowerShell Telemetry
[Environment]::SetEnvironmentVariable("POWERSHELL_TELEMETRY_OPTOUT", "1", "Machine")

# Office Telemetry Registry Keys
$officeKeys = @(
    "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail", "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail",
    "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar", "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar",
    "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Options", "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options",
    "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM", "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM",
    "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry", "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry",
    "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common", "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common",
    "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback", "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback"
)

foreach ($key in $officeKeys) {
    if (!(Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
}

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Name "DisableTelemetry" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "VerboseLogging" -Value 0 -Type DWord -Force
# ... (Additional Office keys follow the same pattern)

# Office Scheduled Tasks
$officeTasks = @(
    "\Microsoft\Office\OfficeTelemetryAgentFallBack", "\Microsoft\Office\OfficeTelemetryAgentLogOn",
    "\Microsoft\Office\OfficeTelemetryAgentFallBack2016", "\Microsoft\Office\OfficeTelemetryAgentLogOn2016",
    "\Microsoft\Office\Office 15 Subscription Heartbeat", "\Microsoft\Office\Office 16 Subscription Heartbeat"
)
foreach ($task in $officeTasks) {
    Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
}

Write-Host ""

##------------------------------------------------------##

# 4. Gaming (Game Mode, Game Bar, Xbox Rec)
Write-Host "-- Disabling Game Mode, Game Bar, and Xbox Recording..." -ForegroundColor Gray
# HKLM Settings
$gameHKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"
if (!(Test-Path $gameHKLM)) { New-Item -Path $gameHKLM -Force | Out-Null }
Set-ItemProperty -Path $gameHKLM -Name "AutoGameModeEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $gameHKLM -Name "AppCaptureEnabled" -Value 0 -Type DWord -Force

# Policies
$gamePolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
if (!(Test-Path $gamePolicy)) { New-Item -Path $gamePolicy -Force | Out-Null }
Set-ItemProperty -Path $gamePolicy -Name "AllowGameDVR" -Value 0 -Type DWord -Force

# HKCU Settings
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "ShowStartupPanel" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord -Force

Write-Host "Optimizations applied successfully! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# --- OneDrive Deep Uninstallation with Timeout ---
Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Checking for OneDrive removal..." -ForegroundColor Cyan

$timeout = 5 # seconds
$wshell = New-Object -ComObject WScript.Shell
$msg = "Do you want to COMPLETELY uninstall OneDrive from this system?`n`n(If you do not answer in $timeout seconds, the answer will be NO)"
$intAnswer = $wshell.Popup($msg, $timeout, "Remove OneDrive?", 4 + 32)

# 6 = Yes | -1 or 7 = Timeout or No
if ($intAnswer -eq 6) {
    Write-Host "-- Starting deep uninstallation of OneDrive..." -ForegroundColor Yellow
    
    $ProgressPreference = "SilentlyContinue"
    
    # Kill OneDrive process
    Write-Host "-- Closing OneDrive process..." -ForegroundColor Gray
    Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2 # Wait for process to fully release handles

    # Run official uninstaller (Check both System32 and SysWOW64)
    $uninstallerX86 = "$env:SystemRoot\System32\OneDriveSetup.exe"
    $uninstallerX64 = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    
    if (Test-Path $uninstallerX64) {
        Write-Host "-- Running official 64-bit uninstaller..." -ForegroundColor Gray
        Start-Process -FilePath $uninstallerX64 -ArgumentList "/uninstall" -Wait
    } elseif (Test-Path $uninstallerX86) {
        Write-Host "-- Running official 32-bit uninstaller..." -ForegroundColor Gray
        Start-Process -FilePath $uninstallerX86 -ArgumentList "/uninstall" -Wait
    }

    # Data Migration (SAFETY FIRST)
    Write-Host "-- Migrating OneDrive files to local folders..." -ForegroundColor Gray
    if (Test-Path "$env:USERPROFILE\OneDrive") {
        # Moves files back to the user root to prevent data loss
        robocopy "$env:USERPROFILE\OneDrive" "$env:USERPROFILE" /mov /e /xj /ndl /nfl /njh /njs /nc /ns /np | Out-Null
    }

    Write-Host "-- Cleaning Registry and Explorer entries..." -ForegroundColor Gray
    # Remove from File Explorer Side Panel
    Remove-Item -Path "HKCR:\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "HKCU:\Software\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    
    # Anti-reinstallation tweaks (Registry)
    Write-Host "-- Applying anti-reinstallation policies..." -ForegroundColor Gray
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
    if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "DisableFileSyncConfig" -Value 1 -Type DWord
    Set-ItemProperty -Path $regPath -Name "PreventNetworkUserAccounts" -Value 1 -Type DWord
    
    Write-Host "-- Removing shortcuts and auto-run triggers..." -ForegroundColor Gray
    Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f 2>$null
    Get-ScheduledTask -TaskName 'OneDrive*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

    Write-Host "-- Deleting leftover folders..." -ForegroundColor Gray
    $folders = @(
        "$env:USERPROFILE\OneDrive",
        "$env:LOCALAPPDATA\OneDrive",
        "$env:LOCALAPPDATA\Microsoft\OneDrive",
        "$env:ProgramData\Microsoft OneDrive",
        "C:\OneDriveTemp"
    )
    foreach ($folder in $folders) {
        if (Test-Path $folder) { 
            # Force close any handle and delete
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue 
        }
    }

    Write-Host "OneDrive removed and blocked successfully! ✅" -ForegroundColor Green
} else {
    Write-Host "OneDrive removal skipped (user declined or timeout). ⏩" -ForegroundColor Yellow
}
Write-Host "--------------------------------------------------------"

##------------------------------------------------------##

# --- Optional Post-Install Scripts (5s Timeout) ---

# 1. StartAllBack Update Blocker
Write-Host "`n--- Optional Tool: StartAllBack Update Blocker ---" -ForegroundColor Cyan
Write-Host "Do you want to run the StartAllBack Update Blocker? [Y/N] (Default: N in 5s): " -NoNewline

# Initialize countdown timer and default answer
$counter = 5
$ans = "n" 

# Countdown loop: Checks for key presses every second
while ($counter -gt 0) {
    if ([console]::KeyAvailable) {
        # Capture the pressed key and stop the timer immediately
        $ans = [console]::ReadKey($true).KeyChar
        Write-Host " [$ans]" -ForegroundColor White
        break
    }
    Write-Host "..$counter " -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
    $counter--
}

# BUFFER FLUSH: Clear any remaining keys from the keyboard buffer.
# This prevents the current input from accidentally skipping the NEXT 5s prompt.
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }

# Execute the external script if 'Y' was selected
if ($ans -eq 'y') {
    Write-Host "`nExecuting StartAllBack Blocker..." -ForegroundColor Green
    
    # Temporarily allow script execution for the current process
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force | Out-Null
    
    try {
        # Download and execute the script directly from GitHub
        iex (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/TogoFire-Home/WorkstationTools/main/StartAllBack-Update-Blocker/Block-StartAllBack.ps1")
    } catch {
        # Error handling in case the URL is down or there is no internet connection
        Write-Host "Failed to execute script from GitHub. Please check your connection." -ForegroundColor Red
    }
} else {
    Write-Host "`nSkipping StartAllBack Blocker..." -ForegroundColor Gray
}

##------------------------------------------------------##

# 2. Microsoft Activation Scripts (MAS)
Write-Host "`n--- Optional Tool: MAS ---" -ForegroundColor Cyan
Write-Host "Do you want to run MAS? [Y/N] (Default: N in 5s): " -NoNewline

$counter = 5
while ($counter -gt 0 -and (-not [console]::KeyAvailable)) {
    Write-Host "..$counter " -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
    $counter--
}

if ([console]::KeyAvailable) {
    $ansMas = [console]::ReadKey($true).KeyChar
    Write-Host ""
} else {
    Write-Host "`nTimeout reached. Skipping..." -ForegroundColor Gray
    $ansMas = "n"
}

if ($ansMas -eq 'y') {
    Write-Host "Running MAS..." -ForegroundColor Green
    $ProgressPreference = "SilentlyContinue"
    irm "https://get.activated.win" | iex
}

Write-Host "`nOptional tools section completed." -ForegroundColor Gray
Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# --- Function to check if a command exists ---
function Test-CommandExists {
    param([string]$Command)
    $null -ne (Get-Command -Name $Command -ErrorAction SilentlyContinue)
}

# --- Function to check for AutoHotkey v2+ installation ---
# This function checks for AutoHotkey v2 or newer, regardless of the subfolder it's installed in.
function Test-AutoHotkeyV2Installed {
    $programFiles = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles)
    $programFilesX86 = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFilesX86)

    # Define possible base directories for AutoHotkey installations
    $ahkBasePaths = @(
        (Join-Path $programFiles "AutoHotkey")
        (Join-Path $programFilesX86 "AutoHotkey")
    )

    # Define possible AutoHotkey executable names
    $ahkExecutables = @(
        "AutoHotkeyU64.exe"
        "AutoHotkeyU32.exe"
        "AutoHotkey.exe" # For cases where it might just be AutoHotkey.exe in PATH
    )

    Write-Host "Searching for AutoHotkey (v2 or newer) in standard paths..."

    foreach ($basePath in $ahkBasePaths) {
        if (Test-Path $basePath) {
            Write-Host "Searching for AutoHotkey executables under: $basePath"
            # Look for executables in $basePath and up to 2 levels deep in subdirectories
            # This covers structures like "AutoHotkey\AutoHotkey.exe" or "AutoHotkey\v2\AutoHotkey.exe"
            $foundExecutables = Get-ChildItem -Path $basePath -Filter "*.exe" -Recurse -Depth 2 -ErrorAction SilentlyContinue | Where-Object { $_.Name -in $ahkExecutables }

            foreach ($exe in $foundExecutables) {
                try {
                    $versionInfo = (Get-Item $exe.FullName).VersionInfo
                    # The ProductMajorPart -ge 2 logic correctly checks for v2 or GREATER
                    if ($versionInfo.ProductMajorPart -ge 2) {
                        Write-Host "AutoHotkey (v2 or newer) detected at '$($exe.FullName)': $($versionInfo.ProductVersion)"
                        return $true
                    }
                } catch {
                    Write-Warning "Could not get AutoHotkey version information for '$($exe.FullName)': $($_.Exception.Message)"
                }
            }
        }
    }

    # Check if autohotkey.exe is in the PATH and its version
    if (Test-CommandExists "autohotkey.exe") {
        Write-Host "AutoHotkey executable 'autohotkey.exe' found in PATH. Checking version..."
        try {
            $ahkPath = (Get-Command "autohotkey.exe").Source
            $versionInfo = (Get-Item $ahkPath).VersionInfo
            # The ProductMajorPart -ge 2 logic correctly checks for v2 or GREATER
            if ($versionInfo.ProductMajorPart -ge 2) {
                Write-Host "AutoHotkey (v2 or newer) detected in PATH: $($versionInfo.ProductVersion)"
                return $true
            } else {
                Write-Host "AutoHotkey found in PATH is an older version ($($versionInfo.ProductVersion)). A compatible version will be installed."
                return $false
            }
        } catch {
            Write-Warning "Could not get AutoHotkey version info from PATH executable: $($_.Exception.Message). Assuming not v2+ or problematic."
            return $false
        }
    }

    Write-Host "AutoHotkey (v2 or newer) not detected via standard paths or PATH."
    return $false
}

Write-Host ""

##------------------------------------------------------##

# --- Function to check for Python v3+ installation ---
function Test-PythonInstalled {
    Write-Host "Checking for Python v3+ installation..."

    # Common Python executable names
    $pythonExecutables = @("python.exe", "python3.exe", "py.exe")

    # Common Python installation paths (beyond just PATH)
    $pythonSearchPaths = @(
        "$env:LOCALAPPDATA\Programs\Python" # Common for Python installers
        "$env:ProgramFiles\Python*"         # Wildcard for specific Python versions (e.g., Python39)
        "$env:ProgramFiles(x86)\Python*"
    )

    # Function to get Python version securely
    function Get-PythonVersion($exePath) {
        try {
            # Use Start-Process with -NoNewWindow and -RedirectStandardOutput to capture output reliably
            # Redirecting StandardError to null.
            $processInfo = New-Object System.Diagnostics.ProcessStartInfo
            $processInfo.FileName = $exePath
            $processInfo.Arguments = "--version"
            $processInfo.UseShellExecute = $false
            $processInfo.RedirectStandardOutput = $true
            $processInfo.RedirectStandardError = $true # Redirect stderr
            $processInfo.CreateNoWindow = $true

            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $processInfo
            $process.Start() | Out-Null
            $process.WaitForExit()

            $output = $process.StandardOutput.ReadToEnd().Trim()
            $errorOutput = $process.StandardError.ReadToEnd().Trim()

            if (![string]::IsNullOrEmpty($errorOutput)) {
                # Log error output but don't let it prevent version parsing if output is still there
                Write-Warning "stderr from '$exePath --version': $errorOutput"
            }

            if ($output -match "Python (\d+)\.(\d+)(\.\d+)?") {
                $major = [int]$Matches[1]
                $minor = [int]$Matches[2]
                return @{ Major = $major; Minor = $minor; FullVersion = $output }
            }
        } catch {
            Write-Warning "Error executing '$exePath --version': $($_.Exception.Message)"
        }
        return $null
    }

    # 1. Check in PATH first
    foreach ($exeName in $pythonExecutables) {
        if (Test-CommandExists $exeName) {
            Write-Host "Found '$exeName' in PATH. Attempting to get version..."
            $versionResult = Get-PythonVersion $exeName
            if ($versionResult) {
                if ($versionResult.Major -ge 3) {
                    Write-Host "Python (v3 or newer) detected via '$exeName': $($versionResult.FullVersion)"
                    return $true
                } else {
                    Write-Host "Python found via '$exeName' ($($versionResult.FullVersion)) is an older version (less than v3). Will attempt installation of compatible version."
                }
            } else {
                Write-Warning "Could not get parseable Python version from '$exeName --version'."
            }
        }
    }

    # 2. Search specific installation paths
    foreach ($searchPath in $pythonSearchPaths) {
        Write-Host "Searching for Python in specific paths like: $searchPath"
        # Find any python.exe, python3.exe, py.exe in these common install locations or their subfolders
        # Using -Filter "*" and then Where-Object to handle multiple patterns correctly
        $foundPythonExecutables = Get-ChildItem -Path $searchPath -Filter "*" -Recurse -Depth 3 -ErrorAction SilentlyContinue |
                                  Where-Object { $_.Name -like "python*.exe" -or $_.Name -eq "py.exe" }

        foreach ($exe in $foundPythonExecutables) {
            Write-Host "Found potential Python executable: $($exe.FullName). Checking version..."
            $versionResult = Get-PythonVersion $exe.FullName
            if ($versionResult) {
                if ($versionResult.Major -ge 3) {
                    Write-Host "Python (v3 or newer) detected at '$($exe.FullName)': $($versionResult.FullVersion)"
                    return $true
                } else {
                    Write-Host "Python found at '$($exe.FullName)' ($($versionResult.FullVersion)) is an older version (less than v3). Will attempt installation of compatible version."
                }
            } else {
                Write-Warning "Could not get parseable Python version from '$($exe.FullName) --version'."
            }
        }
    }

    Write-Host "Python (v3 or newer) not detected via any robust checks. Installation will proceed."
    return $false
}

Write-Host ""

##------------------------------------------------------##

# --- 1. Check for Chocolatey and Install if Missing ---
Write-Host "Checking for Chocolatey installation..."
if (-not (Test-CommandExists "choco")) {
    Write-Host "Chocolatey not found. Attempting to install Chocolatey..."
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "To install Chocolatey, you MUST run this script as an Administrator."
        Write-Error "Please right-click on this .ps1 file and select 'Run as Administrator'."
        exit 1
    }
    try {
        $chocoInstallCommand = "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
        Invoke-Expression $chocoInstallCommand
        Write-Host "Chocolatey installed successfully."
        # Update PATH environment variables for the current session
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Process")
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Error ("Failed to install Chocolatey. Error: {0}" -f $errorMessage)
        Write-Error "Please check your internet connection or try installing manually."
        exit 1
    }
} else {
    Write-Host "Chocolatey is already installed."
}

# --- 2. Check for Winget and Install if Missing ---
Write-Host "Checking for Winget installation..."
if (-not (Test-CommandExists "winget")) {
    Write-Host "Winget not found. Attempting to install Winget..."
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/asheroto/winget-install/master/winget-install.ps1" -OutFile "$env:TEMP\winget-install.ps1" -ErrorAction Stop; & "$env:TEMP\winget-install.ps1"
        Write-Host "Winget installed successfully."
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Error ("Failed to install Winget. Error: {0}" -f $errorMessage)
        Write-Error "Please check your internet connection or try installing manually."
        exit 1
    }
} else {
    Write-Host "Winget is already installed."
}

# --- 3. Check for AutoHotkey (v2+) and Install via Winget if Missing ---
Write-Host "Checking for AutoHotkey (v2 or newer) installation..."
if (-not (Test-AutoHotkeyV2Installed)) {
    Write-Host "AutoHotkey not found or not the correct version. Attempting to install AutoHotkey via Winget..."
    try {
        winget install AutoHotkey.AutoHotkey --silent --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to install AutoHotkey via Winget. Exit code: $LASTEXITCODE"
        } else {
            Write-Host "AutoHotkey installed successfully via Winget."
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Error ("An error occurred while trying to install AutoHotkey via Winget: {0}" -f $errorMessage)
        exit 1
    }
} else {
    Write-Host "AutoHotkey is already installed and is the correct version."
}

Write-Host ""

##------------------------------------------------------##

# --- Function to get PowerShell 7 (pwsh) version ---
function Get-PwshVersion {
    try {
        # Execute pwsh with --version and capture output
        # Use pwsh.exe directly to ensure we're getting the .NET Core PowerShell version
        $versionOutput = (pwsh.exe --version 2>&1).Trim()
        if ($versionOutput -match "PowerShell (\d+\.\d+\.\d+)") {
            return [version]$Matches[1]
        }
    } catch {
        Write-Warning "Could not get PowerShell 7 version: $($_.Exception.Message)"
    }
    return $null
}

Write-Host ""

# --- 3.5. Install/Update PowerShell 7 (pwsh) via Winget ---
Write-Host "Checking for PowerShell 7 (pwsh) installation and updates..."
$pwshInstalledVersion = $null # Initialize to null
if (Test-CommandExists "pwsh") {
    $pwshInstalledVersion = Get-PwshVersion
}

if ($pwshInstalledVersion) {
    Write-Host "PowerShell 7 (pwsh) detected: Version $($pwshInstalledVersion)"

    # Get the latest available version from Winget
    try {
        # Using winget show for more structured output, then parsing
        $wingetShowOutput = winget show Microsoft.PowerShell --exact
        $latestPwshVersionString = ""

        # Extract version from the "Version:" line. This is more robust.
        $versionLine = $wingetShowOutput | Select-String -Pattern "Version:\s*(\S+)"
        if ($versionLine) {
            $latestPwshVersionString = $versionLine.Matches.Groups[1].Value
        }

        if ($latestPwshVersionString -and ($latestPwshVersionString -notlike "*< Not Available >*")) { # Check for "Not Available" case
            $latestPwshVersion = [version]$latestPwshVersionString
            Write-Host "Latest PowerShell 7 version available via Winget: $($latestPwshVersion)"

            if ($pwshInstalledVersion -lt $latestPwshVersion) {
                Write-Host "Installed PowerShell 7 version is older. Attempting to update via Winget..."
                winget upgrade Microsoft.PowerShell -e --accept-package-agreements --accept-source-agreements
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "Failed to update PowerShell 7 via Winget. Exit code: $LASTEXITCODE"
                } else {
                    Write-Host "PowerShell 7 updated successfully via Winget."
                    # Reload PATH for the current session after update, if needed.
                    # This is often done by Winget's installer, but it's good practice for the current session.
                    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
                    Write-Host "Current session PATH reloaded."
                }
            } else {
                Write-Host "PowerShell 7 is already at the latest version or newer. No update needed."
            }
        } else {
            Write-Warning "Could not determine the latest PowerShell 7 version from Winget (output: '$latestPwshVersionString'). Skipping update check."
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Error ("An error occurred while trying to check/update PowerShell 7 via Winget: {0}" -f $errorMessage)
    }
} else {
    Write-Host "PowerShell 7 (pwsh) not found. Attempting to install PowerShell 7 via Winget..."
    try {
        winget install Microsoft.PowerShell -e --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to install PowerShell 7 via Winget. Exit code: $LASTEXITCODE"
        } else {
            Write-Host "PowerShell 7 installed successfully via Winget."
            # The PowerShell 7 installer should add pwsh.exe to the PATH.
            # However, to ensure it's available in the current session, we can reload the Path.
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
            Write-Host "PATH updated for the current session."
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Error ("An error occurred while trying to install PowerShell 7 via Winget: {0}" -f $errorMessage)
        exit 1
    }
}
Write-Host "" # Add a blank line for readability

##------------------------------------------------------##

# --- 4 Optional Category with 5-second Timeout ---
    $optionalPackages = @("fxsound", "github-desktop", "forkgram", "qbittorrent-enhanced", "veracrypt", "element-desktop")
    $shell = New-Object -ComObject WScript.Shell

    Write-Host "`n--- Optional Software Check ---" -ForegroundColor Cyan

    foreach ($package in $optionalPackages) {
        # Popup parameters: (Message, SecondsToWait, Title, ButtonType)
        # ButtonType 4 + 32 = Yes/No buttons + Question Icon
        $msg = "Do you want to install [$package]?`n(Automatically skips in 5 seconds)"
        $response = $shell.Popup($msg, 5, "Optional Installation", 4 + 32)

        if ($response -eq 6) { # 6 = 'Yes' button clicked
            Write-Host "Installing $package..." -ForegroundColor Green
            try {
                if ((choco list --local-only --exact $package -r).Count -eq 0) {
                    choco install $package -y --no-progress
                } else {
                    Write-Host "$package is already installed."
                }
            }
            catch {
                Write-Error "Failed to install $package."
            }
        } else {
            # -1 = Timeout, 7 = 'No' button clicked
            Write-Host "Skipping $package (denied or timeout)." -ForegroundColor Yellow
        }
    }

Write-Host ""

##------------------------------------------------------##

# --- AUTOMATIC MEDIA EXTENSIONS DEPLOYMENT ---
Write-Host "`n[MODULE] Deploying Universal Media Extensions..." -ForegroundColor Cyan

$hevcPath = "$env:TEMP\HEVC_Latest.AppxBundle"

# 1. HEVC CHECK & SMART UPDATE LOGIC
Write-Host ">> Checking system for: HEVC Video Extension (OEM)... " -ForegroundColor Yellow -NoNewline
$hevcPkg = Get-AppxPackage -Name "Microsoft.HEVCVideoExtension" -AllUsers

try {
    # Website scraping for version and link
    $baseUrl = "https://www.free-codecs.com/hevc-video-extensions-from-device-manufacturer_download.htm"
    $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    $page = Invoke-WebRequest -Uri $baseUrl -UserAgent $ua -ErrorAction Stop
    
    # Extracting the newest version string from the site (e.g., "2.4.43.0")
    if ($page.Content -match '(\d+\.\d+\.\d+\.\d+)') { $latestVer = [version]$matches[1] } else { $latestVer = [version]"0.0.0.0" }
    
    # Extracting download link
    $regex = 'download_soft\.php\?d=[a-f0-9]+&s=\d+'
    $linkMatch = [regex]::Match($page.Content, $regex)

    if ($null -ne $hevcPkg) {
        $currentVer = [version]$hevcPkg.Version
        Write-Host "[FOUND: $currentVer]" -ForegroundColor Green

        if ($latestVer -gt $currentVer) {
            Write-Host ">> Status: [UPDATE AVAILABLE: $latestVer]" -ForegroundColor Cyan
            $shouldDownload = $true
        } else {
            Write-Host ">> Status: [ALREADY INSTALLED - UP TO DATE]" -ForegroundColor Gray
            $shouldDownload = $false
        }
    } else {
        Write-Host "[NOT FOUND]" -ForegroundColor White
        $shouldDownload = $true
    }

    # Action: Download and Install if needed
    if ($shouldDownload -and $linkMatch.Success) {
        Write-Host ">> Action: Downloading and Updating to $latestVer... " -ForegroundColor Yellow -NoNewline
        $downloadUrl = "https://www.free-codecs.com/$($linkMatch.Value)"
        Invoke-WebRequest -Uri $downloadUrl -OutFile $hevcPath -UserAgent $ua -MaximumRedirection 5 -ErrorAction Stop
        
        # Force update by installing the newer AppxBundle
        Add-AppxPackage -Path $hevcPath -ErrorAction Stop
        Write-Host "[SUCCESS]" -ForegroundColor Green
    }

} catch {
    Write-Host "[FAILED TO SYNC/INSTALL HEVC]" -ForegroundColor Red
} finally {
    if (Test-Path $hevcPath) { Remove-Item $hevcPath -Force -ErrorAction SilentlyContinue }
}

Write-Host "--------------------------------------------------------"
Write-Host ""

# 2. ADDITIONAL MEDIA EXTENSIONS VIA WINGET (WINGET ALREADY HANDLES UPDATES)
$extensions = @(
    @{ Name = "JPEG XL Image Extension";   ID = "9mzprth5c0tb"; Pkg = "*JxlImageExtension*" }
    @{ Name = "HEIF Image Extension";      ID = "9pmmsr1cgpwg"; Pkg = "*HEIFVideoExtension*" }
    @{ Name = "WebP Image Extension";      ID = "9pg2dk419drg"; Pkg = "*WebpExtension*" }
    @{ Name = "Web Media Extension";       ID = "9n5tdp8vcmhs"; Pkg = "*WebMediaExtensions*" }
    @{ Name = "Raw Image Extension";       ID = "9nctdw2w1bh8"; Pkg = "*RawImageExtension*" }
    @{ Name = "AV1 Video Extension";       ID = "9mvzqvxjbq9v"; Pkg = "*AV1VideoExtension*" }
    @{ Name = "VP9 Video Extension";       ID = "9n4d0msmp0pt"; Pkg = "*VP9VideoExtensions*" }
    @{ Name = "MPEG-2 Video Extension";    ID = "9n95q1zzpmh4"; Pkg = "*MPEG2VideoExtension*" }
)

foreach ($ext in $extensions) {
    Write-Host ">> Processing: $($ext.Name)... " -ForegroundColor Yellow -NoNewline
    
    # WinGet "install" command automatically checks for updates if the package exists
    $null = winget install --id $($ext.ID) --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 > $null
    $exitCode = $LASTEXITCODE
    
    $currentPkg = Get-AppxPackage -Name $($ext.Pkg) -AllUsers | Select-Object -First 1
    $ver = "N/A"

    if ($currentPkg) {
        $ver = $currentPkg.Version
    } else {
        $wingetInfo = winget list --id $($ext.ID) --exact 2>$null | Out-String
        if ($wingetInfo -match '(\d+\.\d+\.\d+\.\d+)') { $ver = $matches[1] }
    }

    if ($exitCode -eq 0) {
        Write-Host "[INSTALLED/UPDATED: $ver]" -ForegroundColor Green
    } elseif ($exitCode -eq -1978335189) {
        Write-Host "[FOUND: $ver]" -ForegroundColor Green
        Write-Host "   -> Status: [ALREADY INSTALLED - UP TO DATE]" -ForegroundColor Gray
    } else { 
        Write-Host "[FAILED / CODE: $exitCode]" -ForegroundColor Red 
    }
}

Write-Host "`n--- Media Extensions Deployment Finished ---" -ForegroundColor Cyan
Write-Host ""

##------------------------------------------------------##

# --- ICAROS THUMBNAILER (IMAGES AND VIDEOS) ---
Write-Host "FIX THUMBNAILS FINAL [2/2]" -ForegroundColor Cyan

# --- ICAROS THUMBNAILER DEPLOYMENT (AUTOMATED GITHUB DELIVERY) ---
Write-Host "`n[MODULE] Checking Icaros Thumbnailer (Images & Video) via GitHub API..." -ForegroundColor Cyan

# Ensure modern TLS 1.2 protocol is used for GitHub API connectivity
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 1. RETRIEVE LATEST METADATA FROM GITHUB REPOSITORY API
try {
    # GitHub API requires a User-Agent header to prevent 403 Forbidden errors
    $headers = @{ "User-Agent" = "PowerShell-Icaros-Updater" }
    $apiUri  = "https://api.github.com/repos/Xanashi/Icaros/releases/latest"
    $apiResponse = Invoke-RestMethod -Uri $apiUri -Headers $headers -ErrorAction Stop
    
    # Extract the tag name (e.g., v3.3.4b1)
    $latestTag = $apiResponse.tag_name 
    
    # Normalize version string for object comparison: v3.3.4b1 -> 3.3.4.1
    $targetVersionStr = ($latestTag -replace '[^0-9.]', '').Replace('b', '.').Trim('.')
    
    # Ensure the string follows the 4-part version format (Major.Minor.Build.Revision)
    $versionParts = $targetVersionStr.Split('.')
    while ($versionParts.Count -lt 4) { 
        $targetVersionStr += ".0"
        $versionParts = $targetVersionStr.Split('.') 
    }
    
    $targetVerObj = [version]$targetVersionStr
    # Filter release assets to find the primary executable installer
    $downloadUrl = ($apiResponse.assets | Where-Object { $_.name -like "*.exe" }).browser_download_url
} catch {
    Write-Host "[ERROR] Failed to communicate with GitHub API: $($_.Exception.Message)" -ForegroundColor Red
    return
}

# Define local environment paths
$tempPath      = "$env:TEMP\Icaros_Latest.exe"
$installDir    = "$env:ProgramFiles\Icaros"
$versionMarker = "$installDir\version.txt"

$shouldInstall = $false
$currentVerObj = [version]"0.0.0.0"

# 2. VALIDATE CURRENT INSTALLATION VIA CUSTOM VERSION MARKER
# Using a local file marker as the primary source of truth due to inconsistent binary metadata in beta releases
if (Test-Path $versionMarker) {
    $content = Get-Content $versionMarker -Raw
    $cleanVer = ($content -replace '[^0-9.]', '').Trim('.')
    if ($cleanVer -match '^\d+(\.\d+){1,3}$') {
        $currentVerObj = [version]$cleanVer
        Write-Host ">> Current Version (Local Marker): $currentVerObj" -ForegroundColor Green
    }
} else {
    Write-Host ">> Current Version: [MARKER NOT FOUND]" -ForegroundColor White
    $shouldInstall = $true
}

# 3. VERSION COMPARISON LOGIC
Write-Host ">> Latest Version (GitHub): $targetVerObj ($latestTag)" -ForegroundColor White

if ($targetVerObj -gt $currentVerObj) {
    Write-Host ">> Status: [UPDATE REQUIRED]" -ForegroundColor Cyan
    $shouldInstall = $true
} else {
    Write-Host ">> Status: [ALREADY UP TO DATE]" -ForegroundColor Gray
    $shouldInstall = $false
}

# 4. EXECUTE DEPLOYMENT PHASE
if ($shouldInstall -and $downloadUrl) {
    # Professional user notification before proceeding
    Write-Host "`n[NOTICE] Starting Icaros Installation..." -ForegroundColor Cyan
    Write-Host ">> Why: Icaros provides advanced Windows Explorer thumbnails for various video AND image formats." -ForegroundColor Gray
    Write-Host ">> Action: Syncing system to version $latestTag to ensure full media preview compatibility." -ForegroundColor Gray
    
    try {
        Write-Host "`n>> Downloading $latestTag... " -ForegroundColor Yellow -NoNewline
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempPath -UserAgent "Mozilla/5.0" -ErrorAction Stop
        Write-Host "[OK]" -ForegroundColor Green

        Write-Host ">> Running Silent Installer (InnoSetup)... " -ForegroundColor Yellow -NoNewline
        # /VERYSILENT: Full automated install | /SUPPRESSMSGBOXES: Suppress prompts | /NORESTART: Avoid reboot
        $process = Start-Process -FilePath $tempPath -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Host "[SUCCESS]" -ForegroundColor Green
            
            # Persist version information to the local marker file
            if (-not (Test-Path $installDir)) { 
                New-Item -Path $installDir -ItemType Directory -Force | Out-Null 
            }
            Set-Content -Path $versionMarker -Value $targetVersionStr -Force
            Write-Host ">> Version marker updated to: $targetVersionStr" -ForegroundColor Gray
        } else {
            Write-Host "[ERROR: EXIT CODE $($process.ExitCode)]" -ForegroundColor Red
        }
    } catch {
        Write-Host "[DOWNLOAD ERROR: $($_.Exception.Message)]" -ForegroundColor Red
    } finally {
        # Cleanup: Remove temporary installer regardless of result
        if (Test-Path $tempPath) { Remove-Item $tempPath -Force -ErrorAction SilentlyContinue }
    }
}

Write-Host "--------------------------------------------------------"

# --- AUTOMATIC APP INSTALLATION (UNATTENDED) ---
Write-Host "`n[MODULE] Deploying Essential Applications..." -ForegroundColor Cyan

$appsToInstall = @(
    @{ Name = "UpNote"; ID = "9mv7690m8f5n" },
    @{ Name = "Notepads"; ID = "9nhl4nsc67wm" },
    @{ Name = "LibreWolf"; ID = "9nvn9sz8kfd7" }
)

$installedCount = 0

foreach ($app in $appsToInstall) {
    Write-Host ">> Processing $($app.Name)... " -ForegroundColor Yellow -NoNewline
    
    # Executing winget with silent flags and agreement bypass
    $installOutput = & winget install --id $($app.ID) --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1
    $exitCode = $LASTEXITCODE

    # Regex to extract the official name from winget output
    $foundName = $app.Name
    if ($installOutput -match "Found (.*?) \[") {
        $foundName = $matches[1]
    }

    if ($exitCode -eq 0) {
        Write-Host "[$foundName] -> [SUCCESSFULLY INSTALLED]" -ForegroundColor Green
        $installedCount++
    } 
    elseif ($exitCode -in @(-1978335135, -1978335189, -1978335191, -1978335221)) {
        Write-Host "[$foundName] -> [ALREADY INSTALLED - SKIPPING]" -ForegroundColor Gray
        $installedCount++
    } 
    else {
        Write-Host "[$foundName] -> [FAILED] Code: $exitCode" -ForegroundColor Red
    }
}

# Final Deployment Summary
Write-Host "`n--- Deployment Summary ---" -ForegroundColor Cyan
Write-Host "Total Apps: $($appsToInstall.Count)" -ForegroundColor White
Write-Host "Completed:  $installedCount" -ForegroundColor Green
Write-Host "--------------------------------------------------------"

##------------------------------------------------------##

# --- INSTALL APPS VIA WINGET (WITH POPUP TIMEOUT) ---
Write-Host "`n[MODULE] Starting Interactive App Installation..." -ForegroundColor Cyan
$appsToInstall = @(
    @{ Name = "FluentFlyout"; ID = "9n45nsm4tnbp" },
    @{ Name = "TubeDigger"; ID = "TubeDigger.TubeDigger" },
    @{ Name = "Signal"; ID = "xp89119p9f2pcq" },
    @{ Name = "Sticky Password"; ID = "xp8lt301zl525k" },
    @{ Name = "WhatsApp"; ID = "9nksqgp7f2nh" },
    @{ Name = "Outlook"; ID = "9nrx63209r7b" },
    @{ Name = "ChatGPT"; ID = "9nt1r1c2hh7j" },
    @{ Name = "Perplexity"; ID = "xp8jnqfbqh6pvf" }
)

$shell = New-Object -ComObject WScript.Shell
$installedCount = 0
$skippedCount = 0

foreach ($app in $appsToInstall) {
    $msg = "Do you want to install [$($app.Name)]?`n`n(This window will auto-close and SKIP in 5 seconds)"
    $title = "Winget Deployment - $($app.Name)"
    
    # Show Popup
    $response = $shell.Popup($msg, 5, $title, 4 + 32)

    if ($response -eq 6) { 
        Write-Host ">> Installing $($app.Name)..." -ForegroundColor Yellow -NoNewline
        $process = winget install --id $($app.ID) -e --silent --accept-package-agreements --accept-source-agreements
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host " [SUCCESS]" -ForegroundColor Green
            $installedCount++
        } else {
            Write-Host " [FAILED/ALREADY INSTALLED]" -ForegroundColor Red
        }
    } 
    else {
        Write-Host ">> Skipped: $($app.Name)" -ForegroundColor Gray
        $skippedCount++
    }
}

Write-Host "`n--- Installation Summary ---" -ForegroundColor Cyan
Write-Host "Apps Installed: $installedCount" -ForegroundColor Green
Write-Host "Apps Skipped:   $skippedCount" -ForegroundColor Yellow
Write-Host "--------------------------------------------------------"

##------------------------------------------------------##

# --- Gaming Essentials Pack (5-second Timeout) ---
Write-Host "`n--- Gaming Essentials Check ---" -ForegroundColor Cyan

# Define the Game Pack IDs (Using Store ID for Xbox App)
$gamePack = @("Valve.Steam", "Discord.Discord", "ElectronicArts.EADesktop", "EpicGames.EpicGamesLauncher", "9MV0B5HZVK9Z")
$gamePackNames = "Steam, Discord, EA Desktop, Epic Games, Xbox App"

$msgGame = "Do you want to install the Gaming Essentials Pack?`n($gamePackNames)`n`n(Automatically skips in 5 seconds)"
$responseGame = $shell.Popup($msgGame, 5, "Gaming Pack Installation", 4 + 32)

if ($responseGame -eq 6) { # 6 = 'Yes' button clicked
    Write-Host "Installing Gaming Essentials Pack..." -ForegroundColor Green
    foreach ($id in $gamePack) {
        Write-Host "Installing $id..." -ForegroundColor Gray
        # Using -e for exact ID matching (essential for the Store ID)
        winget install --id $id -e --accept-source-agreements --accept-package-agreements --silent
    }
    Write-Host "Gaming Pack installation complete. ✅" -ForegroundColor Green
} else {
    Write-Host "Skipping Gaming Pack (denied or timeout)." -ForegroundColor Yellow
}

Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# --- 4.1 Software Installations via Chocolatey ---
Write-Host "Starting software installations via Chocolatey..."

$packagesToInstall = @(
    "7zip"
    "webcamoid"
    "dart-sdk" # Its path handling is separate below
    "qdir"
    "openssh"
    "vscodium"
    "notepadplusplus"
    "git"
    "nano"
    "gh"
    "curl"
    "adb"
    "glab"
    "portx"
    "tabby"
    "vlc"
    "paint.net"
    "fastfetch"
    "qalculate"
    "audacity"
    "lightshot"
    "everything"
    "grepwin"
    "hashcheck"
    "openhashtab"
    "jami"
    "sd-card-formatter"
    "th-ch-youtube-music"
    "winscp.install"
    "zstandard"
    "wiresockvpnclient"
    "winrar"
)

# Handle Python separately before the loop to ensure robust check
if (-not (Test-PythonInstalled)) {
    Write-Host "Python (v3+) not found or not suitable. Attempting to install Python via Chocolatey..."
    try {
        choco install python -y --no-progress
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to install Python. Chocolatey exit code: $LASTEXITCODE"
        } else {
            Write-Host "Python installed successfully."
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Error ("An error occurred while trying to install Python: {0}" -f $errorMessage)
    }
} else {
    Write-Host "Python (v3+) is already installed. Skipping Chocolatey installation for Python."
}
Write-Host "" # Add a blank line for readability


foreach ($package in $packagesToInstall) {
    Write-Host "Checking and installing $package..."
    try {
        # Check if the package is already installed
        # The -r (raw) and --exact flags ensure precise matching and machine-readable output.
        if ((choco list --local-only --exact $package -r).Count -eq 0) {
            choco install $package -y --no-progress
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Failed to install $package. Chocolatey exit code: $LASTEXITCODE"
            } else {
                Write-Host "$package installed successfully."
            }
        } else {
            Write-Host "$package is already installed. Skipping."
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Error ("An error occurred while trying to install {0}: {1}" -f $package, $errorMessage)
    }
    Write-Host ""
}

Write-Host "All specified software installations attempted."
Write-Host ""

##------------------------------------------------------##

# --- 4.2 Hugging Face CLI Installation & Smart Update ---
Write-Host "Checking for Hugging Face CLI (hf)..." -ForegroundColor Cyan

$hfBinary = "$env:USERPROFILE\.local\bin\hf.exe"
$hfInstalled = (Test-CommandExists "hf") -or (Test-Path $hfBinary)
$lastUpdateFile = "$env:USERPROFILE\.hf-cli\.last_update.txt"
$needsUpdateCheck = $true

# Check if we checked for updates recently (within the last 7 days)
if ($hfInstalled -and (Test-Path $lastUpdateFile)) {
    try {
        $lastUpdateStr = Get-Content -Path $lastUpdateFile -Raw -ErrorAction SilentlyContinue
        if ($lastUpdateStr) {
            $lastUpdateDate = [DateTime]::Parse($lastUpdateStr.Trim())
            if ((Get-Date).AddDays(-7) -lt $lastUpdateDate) {
                $needsUpdateCheck = $false
            }
        }
    } catch {
        $needsUpdateCheck = $true
    }
}

# 1. ALWAYS Upgrade Pip first if we're actually going to check for updates or install
if (-not $hfInstalled -or $needsUpdateCheck) {
    Write-Host "-- Upgrading pip..." -ForegroundColor Gray
    python -m pip install --upgrade pip --quiet
}

# 2. Main Logic: Install or Check for Updates
if (-not $hfInstalled) {
    Write-Host "Hugging Face CLI not found. Starting installation..." -ForegroundColor Gray
    try {
        powershell -ExecutionPolicy ByPass -c "irm https://hf.co/cli/install.ps1 | iex"
        
        # Save current date as the last check
        $null = New-Item -Path (Split-Path $lastUpdateFile) -ItemType Directory -Force -ErrorAction SilentlyContinue
        (Get-Date).ToString() | Out-File -FilePath $lastUpdateFile -Force
        
        Write-Host "Hugging Face CLI installed successfully! ✅" -ForegroundColor Green
    } catch {
        Write-Error "Failed to install Hugging Face CLI."
    }
} elseif ($needsUpdateCheck) {
    Write-Host "Checking for Hugging Face CLI updates (Weekly Check)..." -ForegroundColor Gray
    try {
        powershell -ExecutionPolicy ByPass -c "irm https://hf.co/cli/install.ps1 | iex"
        
        # Update the timestamp file
        $null = New-Item -Path (Split-Path $lastUpdateFile) -ItemType Directory -Force -ErrorAction SilentlyContinue
        (Get-Date).ToString() | Out-File -FilePath $lastUpdateFile -Force
        
        Write-Host "Hugging Face CLI check completed. ✅" -ForegroundColor Green
    } catch {
        Write-Host "Update check failed, but 'hf' is already installed. Skipping. ⏩" -ForegroundColor Yellow
    }
} else {
    Write-Host "Hugging Face CLI (hf) is up to date (Last check < 7 days ago). ✅" -ForegroundColor Green
}

Write-Host ""

##------------------------------------------------------##

# --- 5. DART SDK PATH CONFIGURATION ---
# This section ensures 'C:\tools\dart-sdk\bin' is correctly added to the system's 'Path' environment variable.
# It affects all users and requires Administrator privileges.

$dartPathToAdd = "C:\tools\dart-sdk\bin"

Write-Host "--------------------------------------------------------"
Write-Host "Configuring Dart SDK Path:"
Write-Host "--------------------------------------------------------"

Write-Host "Target path to add: '$dartPathToAdd'"

# Get the current System Path environment variable for review
$currentSystemPathBefore = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
Write-Host "Current System Path (BEFORE modification):"
Write-Host "$currentSystemPathBefore"
Write-Host ""

# Check if the Dart path already exists to prevent duplicates
if ($currentSystemPathBefore -notlike "*$dartPathToAdd*") {
    Write-Host "Dart SDK path not found in System Path. Appending now..."
    # Append the new path to the existing System Path
    [System.Environment]::SetEnvironmentVariable("Path", "$currentSystemPathBefore;$dartPathToAdd", "Machine")
    Write-Host "Dart SDK path added to System Path successfully."
} else {
    Write-Host "Dart SDK path '$dartPathToAdd' already exists in the System Path. No action needed."
}

# Get the System Path after potential modification
$currentSystemPathAfter = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
Write-Host "Current System Path (AFTER potential modification):"
Write-Host "$currentSystemPathAfter"
Write-Host ""

Write-Host "Updating Path variable for the current PowerShell session..."
# Update the Path variable for the current PowerShell session to reflect changes immediately.
# This ensures that Dart commands can be used in this session without needing to reopen PowerShell.
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
Write-Host "Current PowerShell session Path updated."
Write-Host ""

Write-Host "Verification: Does the current system Path (machine scope) include '$dartPathToAdd'?"
# Using GetEnvironmentVariable directly for compatibility with older PowerShell
$systemPathIncludesDart = ([System.Environment]::GetEnvironmentVariable("Path", "Machine") -like "*$dartPathToAdd*")
if ($systemPathIncludesDart) {
    Write-Host "Verification successful: System Path includes '$dartPathToAdd'. ✅"
} else {
    Write-Warning "Verification failed: System Path DOES NOT include '$dartPathToAdd'. ❌ Manual check may be required."
}
Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# --- 6. DISABLE STARTUP (DIRECT TASK MANAGER STATUS) ---
Write-Host "Adjusting startup status in Task Manager..." -ForegroundColor Cyan

# Targets
$targets = @(
    "StickyPassword",
    "steam",
    "Discord",
    "Update",
    "EADM",
    "EpicGamesLauncher",
    "Everything", 
    "Lightshot",
    "stpass",
    "Signal",
    "Teams"
)

# Binary Value for "Disabled" (03)
$disabledVal = [byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)

# Registry Paths
$paths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Task",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Task"
)

foreach ($path in $paths) {
    if (Test-Path $path) {
        $key = Get-Item $path
        foreach ($valName in $key.GetValueNames()) {
            $shouldDisable = $false
            
            # Check if the registry item matches any of our targets
            foreach ($t in $targets) {
                if ($valName -match $t) {
                    $shouldDisable = $true
                    break
                }
            }

            if ($shouldDisable) {
                Set-ItemProperty -Path $path -Name $valName -Value $disabledVal -Force
                Write-Host "[$valName] Status changed to DISABLED in: $path" -ForegroundColor Green
            }
        }
    }
}

Write-Host "--------------------------------------------------------"
Write-Host "Done." -ForegroundColor Cyan
Write-Host ""

##------------------------------------------------------##

# --- 7. GITHUB ENVIRONMENT & CASE SENSITIVITY ---
# Configures Git and Windows for Case Sensitivity in the GitHub folder.
Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Configuring GitHub Desktop Environment:" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------"

$GitHubPath = "$HOME\Documents\GitHub"

# Git Configuration
Write-Host "-- Configuring Git global core settings..." -ForegroundColor Gray
if (Test-CommandExists "git") {
    git config --global core.protectNTFS false
    Write-Host "Git: core.protectNTFS set to false. ✅" -ForegroundColor Green
} else {
    Write-Warning "Git not found in PATH. Skipping git config."
}

# Folder Preparation
if (!(Test-Path $GitHubPath)) {
    New-Item -ItemType Directory -Path $GitHubPath -Force | Out-Null
    Write-Host "Created GitHub directory at: $GitHubPath" -ForegroundColor Gray
}

# Windows Case Sensitivity (FSUTIL)
Write-Host "-- Enabling Case Sensitivity on GitHub directory..." -ForegroundColor Gray
# This allows Windows to treat 'File.txt' and 'file.txt' as different files.
try {
    fsutil.exe file SetCaseSensitiveInfo "$GitHubPath" enable
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Case sensitivity enabled successfully! ✅" -ForegroundColor Green
    } else {
        Write-Host "(!) FSUTIL: Folder must be empty or not in use to enable case sensitivity." -ForegroundColor Yellow
    }
} catch {
    Write-Warning "Failed to execute fsutil for case sensitivity."
}

Write-Host "GitHub environment configuration complete." -ForegroundColor Cyan
Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# --- 8. GIT CONTEXT MENU OPTIMIZATION (FORCE SHIFT-ONLY) ---
# Hides "Git GUI Here" and "Git Bash Here" from the standard context menu.
# This ensures they only appear when holding SHIFT + Right Click, as per common debloat standards.
Write-Host "Optimizing Git Context Menu (Force Shift-only access)..." -ForegroundColor Cyan

$gitMenuPaths = @(
    # Standard Classes Root paths
    "HKCR:\Directory\shell\git_shell",
    "HKCR:\Directory\shell\git_gui",
    "HKCR:\Directory\Background\shell\git_shell",
    "HKCR:\Directory\Background\shell\git_gui",
    "HKCR:\LibraryFolder\background\shell\git_gui",
    "HKCR:\LibraryFolder\background\shell\git_shell",

    # Machine-wide paths (High Priority / HKLM)
    "HKLM:\SOFTWARE\Classes\Directory\shell\git_shell",
    "HKLM:\SOFTWARE\Classes\Directory\shell\git_gui",
    "HKLM:\SOFTWARE\Classes\Directory\background\shell\git_shell",
    "HKLM:\SOFTWARE\Classes\Directory\background\shell\git_gui",
    "HKLM:\SOFTWARE\Classes\LibraryFolder\background\shell\git_gui",
    "HKLM:\SOFTWARE\Classes\LibraryFolder\background\shell\git_shell"
)

foreach ($path in $gitMenuPaths) {
    if (Test-Path $path) {
        # Adding the 'Extended' string value hides the entry from the normal menu
        # It will now require SHIFT + Right Click to be visible.
        Set-ItemProperty -Path $path -Name "Extended" -Value "" -Force | Out-Null
        Write-Host "Extended attribute applied: $path" -ForegroundColor Gray
    }
}

Write-Host "Git menu items successfully moved to 'Shift + Right Click'. ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"

##------------------------------------------------------##

# --- 9. GREPWIN CONTEXT MENU PURGE ---
# Removes grepWin from all context menu handlers (Files, Directories, and Background).
# Using native 'reg.exe' for maximum performance and to avoid PowerShell Registry provider overhead.
Write-Host "`n[CLEANUP] Purging grepWin shell entries (Fast Mode)..." -ForegroundColor Cyan

# List of direct Registry commands to ensure complete removal across HKCU and HKLM.
$commands = @(
    'REG DELETE "HKEY_CURRENT_USER\Software\Classes\*\shell\grepWin" /f',
    'REG DELETE "HKEY_CURRENT_USER\Software\Classes\Directory\shell\grepWin" /f',
    'REG DELETE "HKEY_CURRENT_USER\Software\Classes\Directory\Background\shell\grepWin" /f',
    'REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\grepWin" /f',
    'REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\grepWin" /f',
    'REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\Background\shell\grepWin" /f'
)

# Execute each command silently and wait for completion to prevent race conditions.
foreach ($cmd in $commands) {
    # Using 'cmd /c' to execute native reg commands without triggering PowerShell error handling for missing keys.
    Start-Process cmd -ArgumentList "/c $cmd 2>nul" -WindowStyle Hidden -Wait
    Write-Host "." -NoNewline -ForegroundColor Gray
}

Write-Host "`n[SUCCESS] grepWin cleanup completed successfully. ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"

##------------------------------------------------------##
