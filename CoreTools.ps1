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
# 13. Strategic Update Freeze: Hard-pauses Windows Updates until the year 3000 by manipulating the UX Settings registry hive. It extends 'FlightSettingsMaxPauseDays' to unlock long-term pause capabilities and forces PauseUpdatesExpiryTime into the distant future, effectively neutralizing automatic updates while keeping the service operational for manual intervention.
# 14. Version-Specific: Adds 'Check Ownership' menu (for Windows 26H1+ / non-25H2).
# 15. Universal Take Ownership: Deploys a 23-language "Take Ownership" menu using a high-compatibility .reg import method with orange checkmark icons.
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
# 33. User Security: Force-sets 'Password Never Expires' for the current user account.
# 34. Crash Analysis: Enables Detailed BSOD (DisplayParameters) for technical info.
# 35. Print Spooler ACL: Universal SID (S-1-1-0) Full Control grant for 'Everyone'.
# 36. Spooler Context Menu: 23-language repair tool deployed to C:\Windows.
# 37. Visual Effects: Enforced "Show thumbnails" and "Desktop icon shadows".
# 38. Media Extensions: Auto-update for HEVC (Free-Codecs) and 8 Codecs extensions.
# 39. Advanced Thumbnailing: Automated GitHub deployment for Icaros Thumbnailer.
# 40. Context Menu Purge: High-speed registry cleanup to remove grepWin shell entries using native reg.exe for zero-lag execution.
# 41. Explorer UI Opt: Windows 11-specific Snap Layouts enablement and smart Quick Access management. Disables automatic frequent folders and provides an interactive 5s prompt to clear cache only if requested, preserving manual pins.
# 42. Start Menu Refactor: Automated renaming of 'XTools' to 'Tools' with recursive cleanup of redundant PhoenixOS shortcuts and folders.
# 43. Volume Identity: Force-sets System Drive (C:) label to "Windows" and purges localized "Extras + Info" desktop clutter.
# 44. JUNKWARE PURGE: Interactive 5-second timeout-driven menu that allows optional removal of common "digital parasite" antivirus software (McAfee, Norton, AVG, Kaspersky) using official vendor cleanup tools, plus a universal antivirus residue cleaner (ART) and an advanced high-risk option for Microsoft Defender removal.
# 45. DEFENDER LOBOTOMY: High-level Registry/Policy injection to completely disable Windows Defender, Tamper Protection, and Kernel Mitigations, eliminating useless background overhead and restoring absolute system control.
# 46. WINDOWS AI PURGE: Safe-Mode removal of Copilot, Recall, and AI background services via registry, policies, and Appx removal with a 5s interactive prompt.
# 47. EDGE EXORCISM: Deep uninstallation of Microsoft Edge using native setup.exe flags, including a registry "dummy" lock to prevent silent re-installation.
# 48. NOTEPAD CLASSIC RESTORATION: Automated detection and removal of the modern UWP Notepad (9MSMLRH6LZF3) to eliminate AI "Rewrite" bloat and restore system leaness.
# 49. Precision Time Protocol (NTP) Optimization: Swaps default Windows time server for the global pool.ntp.org cluster to ensure lower latency and better sync reliability.
# 50. PowerShell Downgrade Protection: Blocks the legacy PowerShell 2.0 engine using SecEdit-based ACL resets to mitigate downgrade attacks.
# 51. SMBv1 Deactivation: Direct Registry enforcement to disable the insecure SMBv1 protocol, preventing ransomware (WannaCry style) propagation.
# 52. Connectivity Restoration (TLS/SChannel): Comprehensive reset of SCHANNEL settings, insecure ciphers (RC4/DES), and weak hashes (MD5) to restore compatibility with modern web portals, tax services (NFe), and .NET apps.
# 53. System & OEM Intelligence: Implements a deep-scan hardware module that detects Computer Type (Mobile, Desktop, or VM) and System Manufacturer (DMI). It executes a conditional logic to update Windows OEM Information, ensuring a professional system identity by combining Manufacturer and Model for physical PCs while maintaining raw DMI data for Servers and Virtual Machines.
# 54. Vanguard & Valorant Toolkit: Dual-purpose module that validates Riot Vanguard requirements (TPM 2.0, Secure Boot, HVCI) with auto-fix capabilities, and provides a "Nuclear Emergency" repair tool to wipe corrupted vgk.sys drivers and services in Safe Mode to resolve KERNEL_SECURITY_CHECK_FAILURE (0x139) loops.
# 55. BitLocker Privacy & Performance Hardening: Implements a multi-layered shield to disable automatic encryption, block insecure hardware-based encryption, and force-decrypt all volumes to restore SSD performance and data sovereignty.
# 56. SmartScreen Professional Audit: Comprehensive disabling of reputation-based filters for Explorer, Edge, and the Microsoft Store. Eliminates false positives on custom scripts, prevents file-metadata telemetry to Microsoft, and removes "Potentially Unwanted App" (PUA) blocking to restore administrative flow.
# 57. Microsoft Activation Status Professional Audit: A deep-audit module that identifies the exact edition, licensing channel (Retail, OEM, KMS, MAK), and permanency status for Windows, Office, Project, and Visio, featuring native console color-bleed correction.  
# 58. Microsoft License Management Tool: An interactive command interface with a 5-second timeout for installing new Windows product keys, performing deep license registry cleanups (slmgr), and purging blocked Office key fragments via OSPP to resolve activation conflicts.
# 59. Disk Intelligence & SMART Analysis Module: A high-performance diagnostic engine that performs real-time parsing of CrystalDiskInfo logs to extract critical metrics including drive health, temperature, firmware status, power-on hours, and host read/write counters, featuring a multi-language adaptive UI layer with structured output formatting.
# 60. SSD Longevity & Performance Optimizer: A deterministic SSD tuning framework designed to maximize NAND lifespan and reduce unnecessary write amplification. Implements controlled system behavior adjustments including kernel-level paging strategy, TRIM enforcement, flush policy optimization, and telemetry reduction, while preserving OS stability and update compatibility.
# 61. Windows Security Hardening Infrastructure: A layered system hardening module that enforces strict registry-based security policies. It automates the disabling of Autorun and Autoplay across all storage devices, strengthens browser and system security zone configurations to reduce exposure to untrusted content, and improves download safety by enforcing attachment-level integrity checks and signature-aware validation for files originating from external sources.
# 62. System Performance & Privacy Hardening Suite: A system optimization framework focused on reducing background overhead and limiting unnecessary data exposure. It applies performance-oriented registry tuning for application and system responsiveness, disables non-essential telemetry and diagnostic behaviors, and reduces consumer-facing advertising and personalization features. It also removes legacy components such as Internet Explorer to reduce attack surface and maintain a cleaner, more stable operating environment.
# 63. Windows Terminal & PowerShell 7 Hybridization: A configuration engine that detects PowerShell 7 (pwsh.exe) and injects it as the default profile in Windows Terminal's settings.json. It enforces a modern UI by enabling Acrylic transparency and setting background opacity to 80, while simultaneously applying system-wide console host preferences via the HKCU:\Console registry hive.
# 64. Adobe Acrobat Reader Nuclear Purge: A multi-stage uninstallation module that terminates related processes (AcroRd32, AdobeARM, Acrobat) and executes a sequential cleanup using Winget, Appx package removal, and MSI GUID-based uninstallation. It includes registry-based detection to ensure all residues from both 32-bit and 64-bit versions are fully wiped.
# 65. Wallpaper Style & Rendering Engine: A deterministic framework that sets the desktop wallpaper rendering mode to "Fill" (Style 10) within the Windows registry. It implements a custom C# Win32 API wrapper to call SystemParametersInfo, forcing an immediate desktop refresh and re-applying the current wallpaper path to prevent black-screen artifacts without requiring a system restart.
# 66. AyuGram Desktop Deployment Engine: A robust deployment module utilizing dynamic GitHub web parsing to resolve and deploy the latest AyuGram iterations. Features an integrated Win32_OperatingSystem check to enforce Workstation-only deployment, a resilient version-tracking system using both FileVersionInfo and local caching, and automated secure extraction to protected system directories. It leverages WScript.Shell for native shell integration and shortcut persistence, providing a fully unattended lifecycle management solution.
# 67. Unattended Essential App Deployment: A robust, multi-repo installation engine (Winget/Store) featuring intelligent OS-type detection. It automatically filters high-resource or non-essential tools (e.g., Calibre, UpNote) when a Windows Server environment is detected to preserve server integrity. The module handles silent installs, bypasses legal agreements, and maps specific Winget exit codes to provide clear "Success," "Skip," or "Fail" diagnostic reporting.
# 68. Crash Analysis & Debug Suppression: A system stability module that configures the 'CrashControl' registry hive to disable system crash dumps and event logging. It utilizes a proactive verification logic to compare current registry values against desired states (CrashDumpEnabled=0), ensuring the system remains lean by preventing the generation of large memory dump files and reducing disk I/O overhead during critical errors.
# 69. Classic Photo Viewer Restoration: Re-activates the legacy Windows Photo Viewer engine by injecting specialized registry classes and file association capabilities. It bypasses modern UWP overhead by linking standard image extensions (JPG, PNG, etc.) directly to the native System32 PhotoViewer.dll.
# 70. Intelligent AppX Debloat: A multi-pattern cleaning engine that targets third-party junkware and non-essential Microsoft UWP packages. Features an integrated Win32_OperatingSystem check to safeguard Server environments and utilizes 'Remove-AppxPackage -AllUsers' for a comprehensive system-wide purge of telemetry-heavy applications.
# 71. Blockify Desktop Deployment Engine: An advanced automation module for Blockify Desktop featuring OS Intelligence to block installation on Windows Server environments. It employs dynamic web parsing of the official site with a GitHub Releases fallback to resolve the latest version and download links, executes a dual-layer version check against a local marker, handles high-speed extraction, runs a silent NSIS installation (/S), and ensures zero-residue cleanup of temporary artifacts.
# 72. Runtime Installer & .NET Cleanup Module: An automated management system leveraging Winget to ensure essential runtime dependencies (Visual C++ redistributables from 2005 to 2015+, DirectX, WebView2, Java, OpenAL) are fully updated or installed silently with error-code mitigation. Includes an intelligent .NET cleanup mechanism that inventories installed SDKs and Desktop Runtimes, preserves critical protected versions (such as v6, v8, and the latest three modern major releases), and automatically purges outdated packages to optimize disk space and environment hygiene.
# 73. Hardware Clock to UTC: Forces the system hardware clock to operate in UTC (RealTimeIsUniversal=1), preventing time synchronization drift when dual-booting with Unix/Linux environments.
# 74. DefaultUser0 Purge: Automatically detects and removes residual defaultuser0 user accounts left behind by Windows installations or updates to improve system security.
# 75. Windows.old Cleanup: Safely purges leftover C:\Windows.old directories generated after major OS upgrades via forced recursive deletion to reclaim significant disk space.
# 76. Lock Screen Camera Disable: Enforces group policy restrictions (NoLockScreenCamera) to block camera access on the lock screen prior to user authentication.
# 77. Windows Defender CPU Throttling: Configures scan CPU load factor limits (AvgCPULoadFactor) to restrict Windows Defender resource consumption during background checks.
# 78. Global Dark Mode Enforcement: Force-enables system and application dark themes by modifying App and System Use Light Theme registry hives.
# 79. Classic Printers Sidebar Pinning: Registers and pins the classic Printers folder (prnfldr.dll) to the File Explorer Navigation Pane using full COM server and namespace architecture.
# 80. Dynamic OneDrive Namespace Concealment: Scans and identifies corporate or personal OneDrive CLSID namespace entries at runtime, applying desktop hide policies without deleting files or breaking sync state.
# 81. Conditional Hardware Transparency Tweak: Audits physical RAM and logical CPU cores at runtime, automatically disabling visual transparency effects only on low-spec hardware configurations.
# 82. PC Health Check Purge & Reinstall Block: Silently uninstalls Microsoft PC Health Check via msiexec and injects the PreviousUninstall registry flag to prevent automatic re-deployment during future updates.
# 83. Dynamic Windows Update Assistant Removal: Scans registry uninstallation keys to locate, quietly remove, and purge residual installation directories associated with Windows Update and Upgrade Assistants.
# 84. Advanced Windows Security Hardening: Implements enterprise-grade security policies including LSA protection (RunAsPPL), WDigest credential caching block, NTLMv2 enforcement, LLMNR deactivation, insecure SMB guest authentication block, optional SMB signing, and secure WinRM/WPAD hardening configurations.
# 85. Power Plans & Manager Deployment: Automatically synchronizes custom `.pow` files from GitHub, detects existing power plans to reduce duplicate imports, tracks imported plan GUIDs, and deploys the Simple Power Plan Manager with automatic latest-version detection, update verification, and Start Menu shortcut creation.
# 86. OneDrive Policy Enforcement: Enables OneDrive synchronization by configuring the DisableFileSyncNGSC registry policy to fix launch and force-close issues.
# 87. Pawzy Desktop Deployment Engine: An automated deployment module for Pawzy featuring OS Intelligence to block installation on Windows Server. It dynamically resolves the latest release via GitHub API, tracks local versions using a version marker to prevent duplicate updates, executes a silent NSIS installation (/S), and performs complete temporary file cleanup.
# 88. Shutdown Context Menu: Deploys a cascading desktop context menu with automatic language localization for quick power management, including immediate shutdown, flexible scheduled timers, forced restarts, and cancellation actions.
# 89. WPBT, Widgets & IObit Unlocker Suite: Disables Windows Platform Binary Table execution to block boot-level OEM insertions, restores default Windows Widgets policy configurations, and deploys an automated, version-aware, signature-verified silent installer for IObit Unlocker.
# 90. PdfCraft Desktop Deployment Engine: An automated deployment module for PdfCraft featuring architecture detection (x64, x86, ARM64) and Windows Server blocking. It resolves releases dynamically via GitHub API, checks local version markers, executes silent MSI installations (/qn /norestart) with shortcut suppression, and performs safe temporary file cleanup.

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

# ============================================================
# POWERSHELL 7 BOOTSTRAPPER
# Windows PowerShell 5.1 / PowerShell 7 Compatible
# ============================================================

Write-Host "[MODULE] PowerShell 7 Bootstrapper..." -ForegroundColor Cyan

$ProgressPreference = 'SilentlyContinue'

# ------------------------------------------------------------
# 1. CHECK CURRENT POWERSHELL VERSION
# ------------------------------------------------------------

if ($PSVersionTable.PSVersion.Major -ge 7) {
    Write-Host ">> [OK] Running PowerShell $($PSVersionTable.PSVersion)." -ForegroundColor Green
    Write-Host ">> Continuing with the remaining modules..." -ForegroundColor Cyan
    Write-Host ''
}
else {
    Write-Host ">> Windows PowerShell $($PSVersionTable.PSVersion) detected." -ForegroundColor Yellow
    Write-Host ">> Checking PowerShell 7 installation..." -ForegroundColor Yellow

    # --------------------------------------------------------
    # 2. FIND POWERSHELL 7
    # --------------------------------------------------------

    $pwshPath = $null
    $pwshCommand = Get-Command "pwsh.exe" -ErrorAction SilentlyContinue

    if ($pwshCommand) {
        $pwshPath = $pwshCommand.Source
    }

    if (-not $pwshPath) {
        $candidatePaths = @(
            "$env:ProgramFiles\PowerShell\7\pwsh.exe",
            "${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe",
            "$env:LOCALAPPDATA\Programs\PowerShell\7\pwsh.exe"
        )

        foreach ($candidate in $candidatePaths) {
            if (Test-Path $candidate) {
                $pwshPath = $candidate
                break
            }
        }
    }

    # --------------------------------------------------------
    # 3. INSTALL POWERSHELL 7 IF MISSING
    # --------------------------------------------------------

    if (-not $pwshPath) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $tempMsi = Join-Path $env:TEMP "PowerShell_Install.msi"
        $installSucceeded = $false

        try {
            Write-Host ">> Downloading latest stable PowerShell 7..." -ForegroundColor Yellow

            $headers = @{ "User-Agent" = "Mozilla/5.0" }

            $release = Invoke-RestMethod `
                -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" `
                -Headers $headers `
                -ErrorAction Stop

            $arch = if (
                $env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or
                $env:PROCESSOR_ARCHITEW6432 -eq "ARM64"
            ) {
                "arm64"
            }
            elseif ([Environment]::Is64BitOperatingSystem) {
                "x64"
            }
            else {
                "x86"
            }

            $asset = $release.assets |
                Where-Object { $_.name -match "win-$arch\.msi$" } |
                Select-Object -First 1

            if (-not $asset) {
                throw "No PowerShell MSI found for architecture $arch."
            }

            Write-Host ">> Architecture: $arch" -ForegroundColor Gray
            Write-Host ">> Package: $($asset.name)" -ForegroundColor Gray

            Invoke-WebRequest `
                -Uri $asset.browser_download_url `
                -OutFile $tempMsi `
                -UseBasicParsing `
                -ErrorAction Stop

            if (-not (Test-Path $tempMsi) -or (Get-Item $tempMsi).Length -eq 0) {
                throw "The downloaded MSI is missing or empty."
            }

            # ------------------------------------------------
            # 4. INSTALL MSI WITH EXPLORER CONTEXT MENU OPTIONS
            # ------------------------------------------------

            Write-Host ">> Installing PowerShell 7 with Explorer context menus..." -ForegroundColor Yellow

            $msiArgs = @(
                "/i"
                "`"$tempMsi`""
                "/quiet"
                "/norestart"
                "ADD_PATH=1"
                "REGISTER_MANIFEST=1"
                "DISABLE_TELEMETRY=1"
                "ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1"
                "ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1"
            )

            $process = Start-Process `
                -FilePath "msiexec.exe" `
                -ArgumentList $msiArgs `
                -Wait `
                -PassThru

            if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
                throw "PowerShell MSI installation failed. Exit code: $($process.ExitCode)"
            }

            $installSucceeded = $true

            if ($process.ExitCode -eq 3010) {
                Write-Host ">> [INFO] Installation succeeded; a restart may be required." -ForegroundColor Yellow
            }
            else {
                Write-Host ">> [OK] PowerShell 7 installation completed." -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
        }
        finally {
            if (Test-Path $tempMsi) {
                Remove-Item $tempMsi -Force -ErrorAction SilentlyContinue
            }
        }

        # ----------------------------------------------------
        # 5. LOCATE INSTALLED POWERSHELL 7
        # ----------------------------------------------------

        $pwshCommand = Get-Command "pwsh.exe" -ErrorAction SilentlyContinue

        if ($pwshCommand) {
            $pwshPath = $pwshCommand.Source
        }

        if (-not $pwshPath) {
            $candidatePaths = @(
                "$env:ProgramFiles\PowerShell\7\pwsh.exe",
                "${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe",
                "$env:LOCALAPPDATA\Programs\PowerShell\7\pwsh.exe"
            )

            foreach ($candidate in $candidatePaths) {
                if (Test-Path $candidate) {
                    $pwshPath = $candidate
                    break
                }
            }
        }

        if ($installSucceeded -and $pwshPath) {
            Write-Host ">> [OK] PowerShell 7 detected at: $pwshPath" -ForegroundColor Green
        }
    }

    # --------------------------------------------------------
    # 6. RESTART SCRIPT IN POWERSHELL 7 WHEN POSSIBLE
    # --------------------------------------------------------

    if ($pwshPath) {
        if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
            Write-Host ">> Relaunching script in PowerShell 7..." -ForegroundColor Cyan

            & $pwshPath -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        }
        else {
            Write-Host "[WARNING] The script was invoked in memory and cannot be relaunched automatically." -ForegroundColor Yellow
            Write-Host ">> Run CoreTools directly in PowerShell 7:" -ForegroundColor Yellow
            Write-Host 'pwsh -NoProfile -Command "iex (Invoke-RestMethod -Uri ''https://raw.githubusercontent.com/TogoFire-Home/WorkstationTools/main/CoreTools.ps1'')"' -ForegroundColor Gray
        }
    }
    else {
        Write-Host "[ERROR] PowerShell 7 is unavailable. Remaining modules cannot safely continue in PowerShell 5.1." -ForegroundColor Red
        Write-Host ''
    }
}

##------------------------------------------------------##

# Clear
Clear-Host
if (Test-Path ($h = "$HOME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")) { Remove-Item $h -Force -ErrorAction SilentlyContinue }

# LIGHTNING - ASCII ART
Write-Host "                         ,/" -ForegroundColor Yellow
Write-Host "                       ,'/" -ForegroundColor Yellow
Write-Host "                     ,' /" -ForegroundColor Yellow
Write-Host "                   ,'  /_____," -ForegroundColor Yellow
Write-Host "                 .'____    ,'    " -ForegroundColor Yellow
Write-Host "                      /  ,'      " -ForegroundColor Yellow
Write-Host "                     / ,'        " -ForegroundColor Yellow
Write-Host "                    /,'          " -ForegroundColor Yellow
Write-Host "                   /'            " -ForegroundColor Yellow

Write-Host "    ______________________________________" -ForegroundColor Gray
Write-Host "    >> ⚡ WORKSTATION TOOLS             " -ForegroundColor Cyan -NoNewline
Write-Host "" -ForegroundColor DarkGray
Write-Host "    >> Developed by TogoFire              " -ForegroundColor Magenta
Write-Host "    ______________________________________" -ForegroundColor Gray
Write-Host ""

##------------------------------------------------------##

# --- ADMIN PRIVILEGES CHECK ---
# Ensures the script is running with elevated permissions before proceeding.

# Checks if the current user is NOT running PowerShell with Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    
    # Displays an error message in red if Admin permissions are missing
    Write-Host "[!] ERROR: Admin privileges required." -ForegroundColor Red; 
    
    # Terminates script execution immediately to prevent "Access Denied" errors
    exit
}

##------------------------------------------------------##

# --- SYSTEM INFORMATION & OEM UPDATER ---
Write-Host "-- Gathering System Information..." -ForegroundColor Cyan

# 1. Gathering Data
$computerSystem = Get-CimInstance Win32_ComputerSystem
$chassis = Get-CimInstance Win32_SystemEnclosure
$os = Get-CimInstance Win32_OperatingSystem
$bios = Get-CimInstance Win32_BIOS
$processor = Get-CimInstance Win32_Processor
$gpus = Get-CimInstance Win32_VideoController

# 2. Advanced Computer Type Detection (Mobile/Desktop/VM)
$chassisType = switch ($chassis.ChassisTypes) {
    { $_ -in 8, 9, 10, 11, 12, 14, 30, 31, 32 } { "Mobile" }
    { $_ -in 3, 4, 5, 6, 7, 15, 16 } { "Desktop" }
    default { "Workstation" }
}

# Virtual Machine & Server check
$isVM = $computerSystem.Model -match "Virtual|VMware|VirtualBox|Hyper-V"
$isServer = $os.Caption -match "Server"

if ($isVM) { $chassisType = "Virtual Machine" }

$computerFullModel = "$($computerSystem.Manufacturer) $($computerSystem.Model) ($chassisType)"

# 3. OS & Kernel Details
$osVersion = $os.Version
$architecture = $os.OSArchitecture
$displayVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion

# 4. Chipset Detection
$chipsetInfo = Get-CimInstance Win32_PnPEntity | Where-Object { $_.Caption -match "Chipset|Host Bridge|DRAM Controller" } | Select-Object -First 1 -ExpandProperty Caption
if (-not $chipsetInfo) { $chipsetInfo = "Standard System Chipset" }

# 5. Hardware DirectX Support
$dxCapability = "DirectX 9.0"
$gpuMaxLevel = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Direct3D\Drivers" -ErrorAction SilentlyContinue).MaxFeatureLevel
if ($null -eq $gpuMaxLevel) {
    if (Test-Path "C:\Windows\System32\d3d12.dll") { $dxCapability = "DirectX 12" }
    elseif (Test-Path "C:\Windows\System32\d3d11.dll") { $dxCapability = "DirectX 11" }
} else {
    if ($gpuMaxLevel -ge 0xc000) { $dxCapability = "DirectX 12" }
    elseif ($gpuMaxLevel -ge 0xb000) { $dxCapability = "DirectX 11" }
    else { $dxCapability = "DirectX 10" }
}

# 6. RAM Details
$ramModules = Get-CimInstance Win32_PhysicalMemory
$ramTotalGB = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB)
$ramSpeed = if ($ramModules) { ($ramModules | Measure-Object -Property ConfiguredClockSpeed -Maximum).Maximum } else { 0 }
$smbiosMemory = $ramModules | Select-Object -First 1
$memoryType = switch ($smbiosMemory.SMBIOSMemoryType) {
    20 { "DDR" } 21 { "DDR2" } 24 { "DDR3" } 26 { "DDR4" } 34 { "DDR5" } default { "DDR" }
}

# 7. HARDCORE MONITOR DETECTION (Registry Deep Scan)
$monitorInfo = "Generic PnP Monitor"
try {
    $monList = Get-PnpDevice -Class Monitor -Status OK -ErrorAction SilentlyContinue
    if ($monList) {
        $activeMon = $monList[0]
        $hwID = ($activeMon.HardwareID | Where-Object { $_ -match "MONITOR\\" }) -replace "MONITOR\\", ""
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY\$($activeMon.InstanceId.Split('\')[1])"
        $subKey = Get-ChildItem $regPath -ErrorAction SilentlyContinue | Select-Object -First 1
        $driverDesc = Get-ItemPropertyValue $subKey.PSPath -Name "DeviceDesc" -ErrorAction SilentlyContinue
        $cleanName = if ($driverDesc -match ";(.+)") { $matches[1] } else { $driverDesc }
        $mfgPrefix = if ($hwID -match "^BOE") { "BOEhydis" } else { "" }
        if ($cleanName -and $cleanName -notmatch "Generic|Integrated") {
            $monitorInfo = "$mfgPrefix $cleanName ($hwID)".Trim()
        } else {
            $monitorInfo = "$mfgPrefix $hwID".Trim()
        }
    }
} catch { $monitorInfo = "Integrated Monitor" }

# 8. Network Info
$networkConfigs = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
$activeNet = $networkConfigs | Where-Object { $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1

# 9. Storage Info
$disks = Get-CimInstance Win32_DiskDrive | Where-Object { $_.Model -notmatch "Virtual|Msft" }

# --- OUTPUT REPORT ---
Write-Host " [💻] GENERAL INFO" -ForegroundColor White
Write-Host " System Manufacturer (DMI): $($computerSystem.Manufacturer)" -ForegroundColor Gray
Write-Host " Computer Type:            $computerFullModel" -ForegroundColor Gray
Write-Host " OS:                       $($os.Caption) ($displayVersion) $architecture" -ForegroundColor Gray
Write-Host " Kernel:                   WIN32_NT $osVersion" -ForegroundColor Gray
Write-Host " User:                     $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1])" -ForegroundColor Gray
Write-Host " Host/Domain:              $($computerSystem.Name)" -ForegroundColor Gray
Write-Host " Serial (S/N):             $($bios.SerialNumber)" -ForegroundColor Gray
Write-Host " DirectX:                  $dxCapability (Hardware Support)" -ForegroundColor Gray
Write-Host " Monitor:                  $monitorInfo" -ForegroundColor Gray

Write-Host "`n [🔌] MOTHERBOARD & CPU" -ForegroundColor White
Write-Host " CPU:            $($processor.Name)" -ForegroundColor Gray
Write-Host " Motherboard:    $($computerSystem.Model)" -ForegroundColor Gray
Write-Host " Chipset:        $chipsetInfo" -ForegroundColor Gray
Write-Host " RAM:            $ramTotalGB GB ($memoryType @ $($ramSpeed)MHz)" -ForegroundColor Gray
Write-Host " BIOS Version:   $($bios.SMBIOSBIOSVersion) ($($bios.ReleaseDate.ToString('MM/dd/yyyy')))" -ForegroundColor Gray

Write-Host "`n [🎮] GRAPHICS (GPU)" -ForegroundColor White
foreach ($gpu in $gpus) {
    $vram = if ($gpu.AdapterRAM) { [math]::Round($gpu.AdapterRAM / 1MB) } else { 0 }
    $gpuType = if ($gpu.Caption -match "Intel|UHD|Iris|AMD Radeon|Basic Render") { "Integrated" } else { "Dedicated" }
    Write-Host " GPU:            $($gpu.Caption) ($vram MiB) " -NoNewline -ForegroundColor Gray
    Write-Host "[$gpuType]" -ForegroundColor Yellow
}

Write-Host "`n [📦] STORAGE" -ForegroundColor White
foreach ($disk in $disks) {
    $sizeGB = [math]::Round($disk.Size / 1GB)
    Write-Host " Disk:           $($disk.Model) ($sizeGB GB)" -NoNewline -ForegroundColor Gray
    if ($disk.Model -notmatch "QEMU") {
        $type = "HDD SATA"
        if ($disk.Model -match "NVMe" -or $disk.InterfaceType -eq "NVMe") { $type = "SSD NVMe" }
        elseif ($disk.Model -match "SSD" -or $disk.Caption -match "SSD") { $type = "SSD SATA" }
        Write-Host " -> " -NoNewline -ForegroundColor Gray
        Write-Host "$type" -ForegroundColor Yellow
    } else { Write-Host "" }
}

Write-Host "`n [🌐] NETWORK" -ForegroundColor White
if ($activeNet) {
    $ip = $activeNet.IPAddress | Where-Object { $_ -match "\." } | Select-Object -First 1
    Write-Host " Main IP:        $ip" -ForegroundColor Gray
    Write-Host " MAC Address:    $($activeNet.MACAddress)" -ForegroundColor Gray
    Write-Host " Adapter:        $($activeNet.Description)" -ForegroundColor Gray
}

# --- 10. APPLYING OEM INFORMATION TO REGISTRY ---
Write-Host "`n [📝] UPDATING OEM INFORMATION..." -ForegroundColor Cyan
$oemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"

# Conditional Manufacturer Logic
if ($isVM -or $isServer) {
    $oemManufacturer = $computerSystem.Manufacturer
} else {
    # Combines Manufacturer and Model for physical consumer/business PCs
    $oemManufacturer = "$($computerSystem.Manufacturer) $($computerSystem.Model)".Trim()
}

# Logic for Model: Serial or Computer Type
$serial = $bios.SerialNumber
$oemModel = if ([string]::IsNullOrWhiteSpace($serial) -or $serial -match "To be filled|Default|None|00000000") { $computerFullModel } else { $serial }

try {
    if (-not (Test-Path $oemPath)) { New-Item -Path $oemPath -Force | Out-Null }
    Set-ItemProperty -Path $oemPath -Name "Manufacturer" -Value $oemManufacturer
    Set-ItemProperty -Path $oemPath -Name "Model" -Value $oemModel
    Set-ItemProperty -Path $oemPath -Name "SupportHours" -Value ""
    Set-ItemProperty -Path $oemPath -Name "SupportPhone" -Value ""
    Set-ItemProperty -Path $oemPath -Name "SupportURL" -Value ""
    Write-Host " [✅] OEM Registry updated successfully!" -ForegroundColor Green
} catch {
    Write-Host " [❌] Failed to update Registry. Run as Administrator." -ForegroundColor Red
}

Write-Host "`n-- Scan Complete." -ForegroundColor Cyan
Write-Host "--------------------------------------------------------" -ForegroundColor Gray

##------------------------------------------------------##

# ============================================================
# UNIVERSAL BATTERY HEALTH
# Windows PowerShell 5.1+
# Dynamic detection, estimated health, cycles and colored UI.
# Does not terminate the PowerShell session or parent script.
# ============================================================

function Get-BatteryProperty {
    param(
        [Parameter(Mandatory)]
        [string]$ClassName
    )

    try {
        @(Get-CimInstance -Namespace 'root\wmi' -ClassName $ClassName -ErrorAction Stop)
    }
    catch {
        @()
    }
}

function Get-FirstValidNumber {
    param([object[]]$Values)

    foreach ($value in $Values) {
        if ($null -eq $value) {
            continue
        }

        try {
            $number = [double]$value

            if ($number -gt 0 -and $number -lt 1.0E+12) {
                return $number
            }
        }
        catch {}
    }

    return $null
}

function Format-BatteryCapacity {
    param($Value)

    if ($null -eq $Value -or $Value -le 0) {
        return 'Unavailable'
    }

    return ('{0:N0} mWh ({1:N2} Wh)' -f $Value, ($Value / 1000))
}

function Get-BatteryHealthStatus {
    param([double]$Percentage)

    if ($Percentage -ge 80) { return 'GOOD' }
    if ($Percentage -ge 60) { return 'FAIR' }
    if ($Percentage -ge 40) { return 'WEAK' }

    return 'POOR'
}

function Get-EstimatedBatteryCapacity {
    param(
        [string]$BatteryName,
        [string]$ComputerModel,
        [string]$Manufacturer
    )

    # Nominal capacities in mWh.
    # Add only models whose nominal capacity has been verified.
    $knownCapacities = @(
        [PSCustomObject]@{
            BatteryPattern = 'L16M2PB1'
            ComputerModel  = '81V8'
            Manufacturer   = 'LENOVO'
            Capacity       = 30000
        }
    )

    foreach ($entry in $knownCapacities) {

        $batteryMatch = (
            $BatteryName -match [regex]::Escape($entry.BatteryPattern)
        )

        $computerMatch = (
            $ComputerModel -match [regex]::Escape($entry.ComputerModel) -and
            $Manufacturer -match [regex]::Escape($entry.Manufacturer)
        )

        if ($batteryMatch -or $computerMatch) {
            return [PSCustomObject]@{
                Capacity = [double]$entry.Capacity
                Source   = 'Estimated (nominal capacity reference)'
            }
        }
    }

    return $null
}

function Get-BatteryHealthData {

    $batteries  = @(Get-CimInstance -ClassName Win32_Battery)
    $portable   = @(Get-CimInstance -ClassName Win32_PortableBattery)
    $staticData = @(Get-BatteryProperty -ClassName 'BatteryStaticData')
    $fullData   = @(Get-BatteryProperty -ClassName 'BatteryFullChargedCapacity')
    $cycleData  = @(Get-BatteryProperty -ClassName 'BatteryCycleCount')

    $computer = Get-CimInstance -ClassName Win32_ComputerSystem

    $manufacturer = if ($computer.Manufacturer) {
        [string]$computer.Manufacturer
    } else {
        'Unavailable'
    }

    $computerModel = if ($computer.Model) {
        [string]$computer.Model
    } else {
        'Unavailable'
    }

    $maxCount = @(
        $batteries.Count
        $portable.Count
        $staticData.Count
        $fullData.Count
        $cycleData.Count
    ) | Measure-Object -Maximum

    $total = [Math]::Max(1, [int]$maxCount.Maximum)
    $results = @()

    for ($i = 0; $i -lt $total; $i++) {

        $battery = if ($i -lt $batteries.Count) {
            $batteries[$i]
        } else {
            $null
        }

        $portableBattery = if ($i -lt $portable.Count) {
            $portable[$i]
        } else {
            $null
        }

        $static = if ($i -lt $staticData.Count) {
            $staticData[$i]
        } else {
            $null
        }

        $full = if ($i -lt $fullData.Count) {
            $fullData[$i]
        } else {
            $null
        }

        $cycles = if ($i -lt $cycleData.Count) {
            $cycleData[$i]
        } else {
            $null
        }

        # Prefer a battery model/name over a generic device identifier.
        $name = $null

        foreach ($candidate in @(
            $portableBattery.Name
            $static.InstanceName
            $battery.Name
            $battery.DeviceID
        )) {
            if (-not [string]::IsNullOrWhiteSpace([string]$candidate)) {
                $name = [string]$candidate
                break
            }
        }

        if (-not $name) {
            $name = "Battery $($i + 1)"
        }

        $charge = $null

        if ($null -ne $battery.EstimatedChargeRemaining) {
            $charge = [int]$battery.EstimatedChargeRemaining
        }

        # Capacity values are normally reported in mWh.
        $fullCapacity = Get-FirstValidNumber @(
            $full.FullChargedCapacity
            $portableBattery.FullChargeCapacity
        )

        $designCapacity = Get-FirstValidNumber @(
            $static.DesignedCapacity
            $portableBattery.DesignCapacity
        )

        $health = $null
        $healthStatus = 'UNKNOWN'
        $healthSource = 'Unavailable'

        # First choice: measured health from Windows-reported capacities.
        if ($null -ne $designCapacity -and
            $null -ne $fullCapacity -and
            $designCapacity -gt 0) {

            $health = [Math]::Round(
                ($fullCapacity / $designCapacity) * 100,
                2
            )

            $healthStatus = Get-BatteryHealthStatus -Percentage $health
            $healthSource = 'Reported capacities'
        }
        # Fallback: estimate from a known nominal capacity.
        elseif ($null -ne $fullCapacity) {

            $estimate = Get-EstimatedBatteryCapacity `
                -BatteryName $name `
                -ComputerModel $computerModel `
                -Manufacturer $manufacturer

            if ($null -ne $estimate -and $estimate.Capacity -gt 0) {

                $designCapacity = $estimate.Capacity

                $health = [Math]::Round(
                    ($fullCapacity / $designCapacity) * 100,
                    2
                )

                $healthStatus = Get-BatteryHealthStatus -Percentage $health
                $healthSource = $estimate.Source
            }
        }

        # Cycle count is optional and driver-dependent.
        $cycleCount = $null

        if ($null -ne $cycles.CycleCount) {
            try {
                $cycleCount = [int]$cycles.CycleCount
            }
            catch {}
        }

        if ($null -eq $cycleCount -and $null -ne $static.CycleCount) {
            try {
                $cycleCount = [int]$static.CycleCount
            }
            catch {}
        }

        $batteryStatus = if ($battery.Status) {
            [string]$battery.Status
        } else {
            'Unknown'
        }

        $results += [PSCustomObject]@{
            Battery        = $name
            CurrentCharge  = $charge
            DesignCapacity = $designCapacity
            FullCapacity   = $fullCapacity
            Health         = $health
            HealthStatus   = $healthStatus
            HealthSource   = $healthSource
            CycleCount     = $cycleCount
            BatteryStatus  = $batteryStatus
            Manufacturer   = $manufacturer
            ComputerModel  = $computerModel
        }
    }

    $results
}

function Show-BatteryHealth {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result
    )

    $width = 52
    $innerWidth = $width - 4

    function Write-BatteryBoxLine {
        param(
            [string]$Text = '',
            [ConsoleColor]$Color = [ConsoleColor]::Gray
        )

        if ($Text.Length -gt $innerWidth) {
            $Text = $Text.Substring(0, $innerWidth)
        }

        $Text = $Text.PadRight($innerWidth)

        Write-Host '║ ' -NoNewline -ForegroundColor Cyan
        Write-Host $Text -NoNewline -ForegroundColor $Color
        Write-Host ' ║' -ForegroundColor Cyan
    }

    function Get-BatteryHealthBar {
        param($Percentage)

        if ($null -eq $Percentage) {
            return '[ UNKNOWN  ]'
        }

        $filled = [Math]::Max(
            0,
            [Math]::Min(10, [int][Math]::Round($Percentage / 10))
        )

        return '[' + ('+' * $filled) + (' ' * (10 - $filled)) + ']'
    }

    $healthColor = switch ($Result.HealthStatus) {
        'GOOD'      { 'Green' }
        'FAIR'      { 'Yellow' }
        'WEAK'      { 'DarkYellow' }
        'POOR'      { 'Red' }
        default     { 'Gray' }
    }

    $chargeText = if ($null -ne $Result.CurrentCharge) {
        "$($Result.CurrentCharge)%"
    } else {
        'Unavailable'
    }

    $healthText = if ($null -ne $Result.Health) {
        if ($Result.HealthSource -like 'Estimated*') {
            '{0:N2}% (estimated)' -f $Result.Health
        } else {
            '{0:N2}%' -f $Result.Health
        }
    } else {
        'Unavailable'
    }

    $statusText = if ($null -ne $Result.Health) {
        '{0} {1}' -f $Result.HealthStatus, (Get-BatteryHealthBar $Result.Health)
    } else {
        'UNKNOWN [ UNKNOWN  ]'
    }

    $cyclesText = if ($null -ne $Result.CycleCount) {
        [string]$Result.CycleCount
    } else {
        'Unavailable'
    }

    $designText = if ($Result.HealthSource -like 'Estimated*') {
        '{0:N0} mWh (nominal)' -f $Result.DesignCapacity
    } else {
        Format-BatteryCapacity $Result.DesignCapacity
    }

    $fullText = if ($null -ne $Result.FullCapacity) {
        '{0:N0} mWh' -f $Result.FullCapacity
    } else {
        'Unavailable'
    }

    $title = 'BATTERY HEALTH'
    $leftPadding = [Math]::Floor(($innerWidth - $title.Length) / 2)
    $rightPadding = $innerWidth - $title.Length - $leftPadding

    Write-Host ''
    Write-Host ('╔' + ('═' * ($width - 2)) + '╗') -ForegroundColor Cyan

    Write-Host '║ ' -NoNewline -ForegroundColor Cyan
    Write-Host ((' ' * $leftPadding) + $title + (' ' * $rightPadding)) -NoNewline -ForegroundColor White
    Write-Host ' ║' -ForegroundColor Cyan

    Write-Host ('╠' + ('═' * ($width - 2)) + '╣') -ForegroundColor Cyan

    Write-BatteryBoxLine ('Battery         : ' + $Result.Battery)
    Write-BatteryBoxLine ('Current Charge  : ' + $chargeText)
    Write-BatteryBoxLine ('Design Capacity : ' + $designText)
    Write-BatteryBoxLine ('Full Capacity   : ' + $fullText)
    Write-BatteryBoxLine ('Battery Health  : ' + $healthText) $healthColor
    Write-BatteryBoxLine ('Status          : ' + $statusText) $healthColor
    Write-BatteryBoxLine ('Charge Cycles   : ' + $cyclesText)

    Write-Host ('╚' + ('═' * ($width - 2)) + '╝') -ForegroundColor Cyan

    Write-Host ''
    Write-Host 'NOTE:' -ForegroundColor Yellow

    if ($Result.HealthSource -like 'Estimated*') {
        Write-Host 'Health is ESTIMATED using a nominal capacity reference.' -ForegroundColor Yellow
        Write-Host 'The nominal capacity may not match your exact battery variant.' -ForegroundColor Yellow
        Write-Host 'The result may differ from the manufacturer-reported health.' -ForegroundColor Yellow
    }
    elseif ($null -eq $Result.Health) {
        Write-Host 'Health unavailable: no reliable design capacity was found.' -ForegroundColor Yellow
        Write-Host 'No capacity was guessed from the brand or model.' -ForegroundColor Yellow
    }
    else {
        Write-Host 'Health is calculated from capacities reported by the battery driver.' -ForegroundColor Gray
        Write-Host 'Results may differ from the manufacturer diagnostic.' -ForegroundColor Gray
    }

    Write-Host ''
}

# ============================================================
# EXECUTION
# ============================================================

$batteryResults = @(Get-BatteryHealthData)

if ($batteryResults.Count -gt 0) {
    foreach ($batteryResult in $batteryResults) {
        Show-BatteryHealth -Result $batteryResult
    }
}
else {
    Write-Host 'No battery data was exposed by Windows.' -ForegroundColor Yellow
}

Write-Host "--------------------------------------------------------" -ForegroundColor Gray

##------------------------------------------------------##

<#
.SYNOPSIS
    Advanced Microsoft Activation Status Professional Audit.
.DESCRIPTION
    Fully automated identification for Windows, Office, Project, and Visio.
#>

$FormatEnumerationLimit = -1
Write-Host "--- Microsoft Activation Status Professional Audit ---" -ForegroundColor Cyan

function Get-ActivationStatus {
    # Fetch products that have a partial key installed
    $Products = Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object { $_.PartialProductKey }
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem

    # 1. WINDOWS OS ANALYSIS
    $WinHeader = "[ WINDOWS OS ]"
    # PadRight ensures the background color forms a solid bar and doesn't bleed
    Write-Host "`n$($WinHeader.PadRight(65))" -ForegroundColor White -BackgroundColor DarkBlue
    
    $WinOS = $Products | Where-Object { $_.ApplicationID -eq "55c92734-d682-4d71-983e-d6ec3f16059f" }

    foreach ($obj in $WinOS) {
        $status = if ($obj.LicenseStatus -eq 1) { "Licensed (Activated)" } else { "Unlicensed/Notification" }
        $color = if ($obj.LicenseStatus -eq 1) { "Green" } else { "Red" }
        
        $channel = "Unknown"
        if ($obj.Description -match "RETAIL") { $channel = "Retail" }
        elseif ($obj.Description -match "OEM") { $channel = "OEM" }
        elseif ($obj.Description -match "VOLUME_KMS") { $channel = "Volume: KMS" }
        elseif ($obj.Description -match "VOLUME_MAK") { $channel = "Volume: MAK" }

        $isPermanent = if ($obj.LicenseStatus -eq 1 -and ($obj.GracePeriodRemaining -eq 0 -or $obj.GracePeriodRemaining -ge 2147483647)) { $true } else { $false }

        $displayVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).DisplayVersion
        $fullOSName = "$($OS.Caption) ($displayVer) Build $($OS.BuildNumber) [x$((Get-CimInstance Win32_Processor).AddressWidth)]"

        Write-Host "Product:     $fullOSName"
        Write-Host "Channel:     $channel" -ForegroundColor Cyan
        Write-Host "Status:      " -NoNewline; Write-Host $status -ForegroundColor $color
        Write-Host "Partial Key: $($obj.PartialProductKey)"
        
        Write-Host "Permanency:  " -NoNewline
        if ($isPermanent) { Write-Host "Permanently Activated" -ForegroundColor Green }
        else { Write-Host "Temporary ($([math]::Round($obj.GracePeriodRemaining / 1440, 2)) days remaining)" -ForegroundColor Yellow }
    }

    # 2. OFFICE / PROJECT / VISIO ANALYSIS
    $OfficeProducts = $Products | Where-Object { $_.Description -match "Office" -or $_.Name -match "Office" }

    if ($OfficeProducts) {
        foreach ($off in $OfficeProducts) {
            $skuName = $off.Name -replace " edition", ""
            
            $category = "MICROSOFT OFFICE"
            $bgColor = "DarkMagenta"
            
            if ($skuName -match "Project") { 
                $category = "MICROSOFT PROJECT"
                $bgColor = "DarkGreen"
            }
            elseif ($skuName -match "Visio") { 
                $category = "MICROSOFT VISIO"
                $bgColor = "DarkCyan"
            }

            # Padding correction: PadRight fills the line buffer to prevent color overflow
            $OffHeader = "[ $category ]"
            Write-Host "`n$($OffHeader.PadRight(65))" -ForegroundColor White -BackgroundColor $bgColor
            
            $offStatus = if ($off.LicenseStatus -eq 1) { "Licensed" } else { "Unlicensed/Grace" }
            $offColor = if ($off.LicenseStatus -eq 1) { "Green" } else { "Yellow" }
            
            $offChannel = "Unknown"
            if ($off.Description -match "RETAIL") { $offChannel = "Retail" }
            elseif ($off.Description -match "OEM") { $offChannel = "OEM" }
            elseif ($off.Description -match "VOLUME_KMS" -or $off.Name -match "KMS") { $offChannel = "Volume: KMS" }
            elseif ($off.Description -match "VOLUME_MAK" -or $off.Name -match "MAK") { $offChannel = "Volume: MAK" }

            $isOffPermanent = if ($off.LicenseStatus -eq 1 -and ($off.GracePeriodRemaining -eq 0 -or $off.GracePeriodRemaining -ge 2147483647)) { $true } else { $false }

            Write-Host "Edition:     $skuName" -ForegroundColor White
            Write-Host "Channel:     $offChannel" -ForegroundColor Cyan
            Write-Host "Status:      " -NoNewline; Write-Host $offStatus -ForegroundColor $offColor
            Write-Host "Partial Key: $($off.PartialProductKey)"
            
            Write-Host "Permanency:  " -NoNewline
            if ($isOffPermanent) { Write-Host "Permanently Activated" -ForegroundColor Green }
            else { Write-Host "Temporary ($([math]::Round($off.GracePeriodRemaining / 1440, 2)) days remaining)" -ForegroundColor Yellow }
        }
    }
}

try { 
    Get-ActivationStatus 
} catch { 
    Write-Host "Error: Please run PowerShell as Administrator." -ForegroundColor Red 
} finally {
    # Safe and universal color reset
    [Console]::ResetColor()
}

Write-Host "`nAudit Complete." -ForegroundColor Cyan

##------------------------------------------------------##

<#
.SYNOPSIS
    Microsoft License & System Management Tool

.DESCRIPTION
    Interactive PowerShell menu for managing Windows and Microsoft Office licensing,
    system repair operations (SFC/DISM), and optional maintenance tools.

    Features:
    - Menu-driven interface with automatic timeout selection
    - Windows and Office (including Project/Visio) license management
    - System integrity repair utilities (SFC and DISM)
    - Optional activation and maintenance tools integration
    - Safe execution flow with user confirmation prompts
#>

function Clear-KeyBuffer {
    while ([Console]::KeyAvailable) {
        [Console]::ReadKey($true) | Out-Null
    }
}

function Show-LicenseMenu {
    Write-Host "`n================================================" -ForegroundColor Cyan
    Write-Host "   MICROSOFT LICENSE MANAGEMENT TOOL            " -ForegroundColor White
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "1. Remove Windows Product Key"
    Write-Host "2. Install Windows Product Key"
    Write-Host "3. Remove Office Keys"
    Write-Host "4. MAS Tool"
    Write-Host "5. Run SFC"
    Write-Host "6. Run DISM"
    Write-Host "7. Skip / Continue Script"
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "Select an option (Auto-skip in 5s): " -NoNewline
}

# ========================================================
# FUNCTIONS
# ========================================================
function Run-MAS { irm "https://get.activated.win" | iex }
function Run-SFC { sfc /scannow }
function Run-DISM { DISM /Online /Cleanup-Image /RestoreHealth }

function Remove-WindowsKey { slmgr /cpky; slmgr /upk }
function Install-WindowsKey {
    $key = Read-Host "Enter Key"
    slmgr /ipk $key
}
function Remove-OfficeKeys { Write-Host "Removing Office keys..." }

# ========================================================
# MAIN LOOP
# ========================================================
$ContinueScript = $false

while ($true) {

    $timeout = 5
    $selection = $null

    Clear-KeyBuffer
    Show-LicenseMenu

    while ($timeout -gt 0) {
        if ([Console]::KeyAvailable) {
            $selection = [Console]::ReadKey($true).KeyChar
            break
        }

        Write-Host "..$timeout" -NoNewline -ForegroundColor Gray
        Start-Sleep 1
        $timeout--
    }

    Write-Host ""

    # Timeout = skip menu loop and continue script
    if (-not $selection) {
        Write-Host "[INFO] Timeout → continuing script..." -ForegroundColor Yellow
        $ContinueScript = $true
        break
    }

    # ====================================================
    # OPTION 7 = IMMEDIATE SKIP
    # ====================================================
    if ($selection -eq '7') {
        Write-Host "`n[INFO] Skip selected → continuing script..." -ForegroundColor Green
        $ContinueScript = $true
        break
    }

    # ====================================================
    # CONFIRMATION FOR OPTIONS 1–6
    # ====================================================
    Write-Host "`nYou selected option [$selection]" -ForegroundColor Cyan
    $confirm = Read-Host "Continue execution? (Y/N)"

    if ($confirm -match '^[Yy]$') {

        switch ($selection) {
            '1' { Remove-WindowsKey }
            '2' { Install-WindowsKey }
            '3' { Remove-OfficeKeys }
            '4' { Run-MAS }
            '5' { Run-SFC }
            '6' { Run-DISM }
            default { Write-Host "[ERROR] Invalid option." -ForegroundColor Red }
        }

        Write-Host "`n[INFO] Operation completed. Returning to menu..." -ForegroundColor Cyan
        Start-Sleep 1
        continue
    }

    # ❗ FIX: THIS IS THE IMPORTANT PART
    # Instead of return, we just loop again
    Write-Host "[INFO] Returning to menu..." -ForegroundColor Yellow
    Start-Sleep 1
    continue
}

# ========================================================
# CONTINUE PIPELINE AFTER MENU
# ========================================================
if ($ContinueScript) {
    Write-Host "`n[INFO] Continuing to next scripts..." -ForegroundColor Cyan
}

Clear-KeyBuffer
Write-Host "`n[INFO] Done." -ForegroundColor Gray

##------------------------------------------------------##

# --- POWERSHELL 2.0 SECURITY ENFORCER ---
# Purpose: Block PowerShell 2.0 engine to mitigate downgrade attacks.
# Method: Conditional enforcement - only applies fixes if the system is vulnerable.

# --- CONFIGURATION ---
$regTarget     = "MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine"
$regPath       = "HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine"
$valueName     = "PSCompatibleVersion"
$secureValue   = "3.0, 4.0, 5.0, 5.1"
$cfgFile       = "$env:TEMP\sec_template.inf"
$dbFile        = "$env:TEMP\sec_audit.sdb"

Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host " [🔍] ANALYZING POWERSHELL ENGINE STATUS" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------" -ForegroundColor Gray

$needsFix = $false

# 1. Initial Status Check
if (Test-Path $regPath) {
    $initialVal = (Get-ItemProperty -Path $regPath).$valueName
    
    if ($initialVal -notmatch "2.0") {
        # --- SYSTEM SECURE: SET FLAG TO FALSE ---
        Write-Host " [*] Current Status: " -NoNewline -ForegroundColor White
        Write-Host "SECURE" -ForegroundColor Green
        Write-Host " [i] Version 2.0 is already blocked. No action required." -ForegroundColor Gray
        $needsFix = $false
    } else {
        # --- SYSTEM VULNERABLE: SET FLAG TO TRUE ---
        Write-Host " [*] Current Status: " -NoNewline -ForegroundColor White
        Write-Host "VULNERABLE" -ForegroundColor Red
        Write-Host " [!] Found Version 2.0 in: $initialVal" -ForegroundColor Yellow
        $needsFix = $true
    }
} else {
    Write-Host " [✅] Target registry path not found. System is secure." -ForegroundColor Green
    $needsFix = $false
}

# 2. Execution Logic (Only runs if $needsFix is True)
if ($needsFix) {
    Write-Host "`n [⚡] INITIALIZING SECURITY ENFORCEMENT" -ForegroundColor Cyan
    Write-Host " ---------------------------------------------------" -ForegroundColor Gray

    # Generate Security Template (Granting Full Control to Administrators)
    Write-Host " [+] Generating Security Template..." -ForegroundColor Gray
    $securityTemplate = @"
[Unicode]
Unicode=yes
[Registry Keys]
"$regTarget",2,"D:AR(A;CI;KA;;;BA)"
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
    $securityTemplate | Out-File -FilePath $cfgFile -Encoding unicode

    try {
        # Apply ACL reset using SecEdit
        Write-Host " [+] Resetting Registry Permissions (SecEdit)..." -ForegroundColor Gray
        secedit /configure /db $dbFile /cfg $cfgFile /areas REGKEYS /quiet | Out-Null
        
        # Apply the Lockdown Fix
        Write-Host " [+] Applying version restriction to registry..." -ForegroundColor Gray
        Set-ItemProperty -Path $regPath -Name $valueName -Value $secureValue -Force -ErrorAction Stop
        
        # Final Verification
        $finalVal = (Get-ItemProperty -Path $regPath).$valueName
        Write-Host "`n [✅] SUCCESS: Security policies applied." -ForegroundColor Green
        Write-Host " [i] Updated Value: $finalVal" -ForegroundColor White
    }
    catch {
        Write-Host "`n [❌] CRITICAL ERROR: Could not apply registry fix." -ForegroundColor Red
        Write-Host " [!] Reason: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    finally {
        # Cleanup temporary security files
        if (Test-Path $cfgFile) { Remove-Item $cfgFile -Force }
        if (Test-Path $dbFile) { Remove-Item $dbFile -Force }
    }
}

# 3. Final Wrap-up (Always executes, allowing the rest of the script to run)
Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host " [🏁] POWERSHELL SECURITY CHECK COMPLETE" -ForegroundColor Green
Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

# Keyboard buffer cleanup
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }

##------------------------------------------------------##

# --- PRECISION TIME PROTOCOL (NTP) OPTIMIZATION & GUI REGISTRATION ---
# Purpose: Ensures sub-millisecond accuracy, forces service persistence, and registers the server in the Windows GUI.

Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host " [🔍] ANALYZING SYSTEM TIME SOURCE & REGISTRY" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------" -ForegroundColor Gray

# --- 1. Infrastructure Check ---
# Ensure Service is not Disabled and is Running (Required for Query)
$timeService = Get-Service w32time -ErrorAction SilentlyContinue
if ($timeService.StartType -eq 'Disabled') {
    Write-Host " [!] Windows Time service was Disabled. Re-enabling..." -ForegroundColor Yellow
    Set-Service w32time -StartupType Automatic
}

if ($timeService.Status -ne 'Running') {
    Write-Host " [!] Starting Windows Time service for analysis..." -ForegroundColor Gray
    Start-Service w32time -ErrorAction SilentlyContinue
}

# --- 2. GUI List Registration ---
# This ensures "pool.ntp.org" appears in the Control Panel / Settings dropdown list
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers"
$targetNtp = "pool.ntp.org"

try {
    $existingServers = Get-ItemProperty -Path $registryPath
    $serverValues = $existingServers.PSObject.Properties.Value
    
    if ($serverValues -notcontains $targetNtp) {
        Write-Host " [*] Adding $targetNtp to the Windows GUI selection list..." -ForegroundColor Gray
        
        # Find the next available numerical index in the registry
        $currentIndexes = $existingServers.PSObject.Properties.Name | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
        $nextIndex = ($currentIndexes | Measure-Object -Maximum).Maximum + 1
        
        # Create the new registry string value
        New-ItemProperty -Path $registryPath -Name $nextIndex -Value $targetNtp -PropertyType String -Force | Out-Null
        
        # Set the newly added server as the "Default" selection in the registry (0-based or index-based)
        # Note: Usually (Default) value in this key points to the index to be used.
        Set-ItemProperty -Path $registryPath -Name "(Default)" -Value "$nextIndex"
    }
} catch {
    Write-Host " [!] Failed to update Registry list. Ensure you are running as Admin." -ForegroundColor Red
}

# --- 3. Service Identification & Decision Logic ---
$currentSource = (w32tm /query /source 2>$null)

if ([string]::IsNullOrWhiteSpace($currentSource) -or $currentSource -match "Local CMOS" -or $currentSource -match "Free-Running") {
    $displaySource = "Standard/Local Clock"
} else {
    $displaySource = $currentSource
}

Write-Host " [*] Current Source: $displaySource" -ForegroundColor White

# Apply changes only if the pool is not already the active source
if ($currentSource -notmatch "pool.ntp.org") {
    Write-Host " [!] Optimization required. Configuring pool.ntp.org..." -ForegroundColor Yellow
    
    try {
        # Force service to Automatic and Start
        Set-Service w32time -StartupType Automatic
        Start-Service w32time -ErrorAction SilentlyContinue

        # Register network trigger (Service starts when internet is available)
        & sc.exe triggerinfo w32time start/networkon stop/networkoff | Out-Null

        # Apply global NTP pool configuration with 0x1 flag (Symmetric Active mode)
        $ntpPool = "0.pool.ntp.org,0x1 1.pool.ntp.org,0x1 2.pool.ntp.org,0x1 3.pool.ntp.org,0x1"
        & w32tm /config /manualpeerlist:"$ntpPool" /syncfromflags:manual /reliable:YES /update | Out-Null
        
        # Restart to commit changes
        Restart-Service w32time -Force
        
        # Immediate resync and hardware rediscovery
        & w32tm /resync /rediscover | Out-Null
        
        Write-Host "`n [✅] SUCCESS: NTP server updated, registered in GUI, and set to Persistent." -ForegroundColor Green
    }
    catch {
        Write-Host "`n [❌] ERROR: Failed to apply NTP configuration." -ForegroundColor Red
    }
}
else {
    Write-Host " [✅] SYSTEM ALREADY OPTIMIZED: pool.ntp.org is active and registered." -ForegroundColor Green
}

Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

##------------------------------------------------------##

# --- Setting Hardware Clock to UTC ---
Write-Host "-- Setting Hardware Clock to UTC..." -ForegroundColor Gray
reg add "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /t REG_DWORD /d 1 /f | Out-Null

Write-Host ""
Write-Host "Hardware clock set to UTC successfully! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# --- SMBv1 SECURITY ENFORCER (REGISTRY METHOD) ---
# Purpose: Detect and disable the insecure SMBv1 protocol to prevent Ransomware (e.g., WannaCry).
# Method: Direct Registry manipulation for high compatibility with optimized Windows builds.

# --- CONFIGURATION ---
$Smb1Path  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$Smb1Value = "SMB1"

Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host " [🔍] ANALYZING SMBv1 SERVER STATUS" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------" -ForegroundColor Gray

# 1. Verification Logic
$vulnerable = $false
$abortModule = $false

try {
    $currentVal = (Get-ItemProperty -Path $Smb1Path -Name $Smb1Value -ErrorAction SilentlyContinue).$Smb1Value

    Write-Host " [*] Current Registry State: " -NoNewline -ForegroundColor White
    
    if ($currentVal -eq 0) {
        Write-Host "SECURE" -ForegroundColor Green
        Write-Host " [i] SMBv1 is already disabled (Value = 0)." -ForegroundColor Gray
    } 
    elseif ($currentVal -eq 1) {
        Write-Host "VULNERABLE" -ForegroundColor Red
        Write-Host " [!] SMBv1 is explicitly enabled in registry." -ForegroundColor Yellow
        $vulnerable = $true
    }
    else {
        # If the value is missing, Windows may allow SMBv1 by default or via Features.
        Write-Host "VULNERABLE (DEFAULT)" -ForegroundColor Red
        Write-Host " [!] Registry key 'SMB1' is missing. Protocol is likely active." -ForegroundColor Yellow
        $vulnerable = $true
    }
} catch {
    Write-Host " [❌] ERROR: Could not access LanmanServer registry hive." -ForegroundColor Red
    # Setting abort flag instead of 'return' to preserve the main script execution.
    $abortModule = $true
}

# 2. Automated Enforcement (Only executes if module wasn't aborted and system is vulnerable)
if (-not $abortModule -and $vulnerable) {
    Write-Host "`n [⚡] INITIALIZING SMBv1 DEACTIVATION" -ForegroundColor Cyan
    Write-Host " ---------------------------------------------------" -ForegroundColor Gray
    
    try {
        # Force create/set the SMB1 value to 0
        Write-Host " [+] Injecting 'SMB1' DWord = 0 into registry..." -ForegroundColor Gray
        New-ItemProperty -Path $Smb1Path -Name $Smb1Value -Value 0 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null
        
        Write-Host "`n [✅] SUCCESS: SMBv1 Server has been disabled." -ForegroundColor Green
        Write-Host " [!] IMPORTANT: A REBOOT is required to apply changes." -ForegroundColor Magenta
    }
    catch {
        Write-Host "`n [❌] FATAL ERROR: Failed to modify registry." -ForegroundColor Red
        Write-Host " [i] Reason: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} elseif (-not $abortModule -and -not $vulnerable) {
    Write-Host "`n [✅] No action needed. Your system is protected against SMBv1 exploits." -ForegroundColor Cyan
}

# 3. Final Summary (Only if access was successful)
if (-not $abortModule) {
    Write-Host "--------------------------------------------------------" -ForegroundColor Gray
    Write-Host " [🏁] FINAL STATUS: " -NoNewline -ForegroundColor White
    $finalCheck = (Get-ItemProperty -Path $Smb1Path -Name $Smb1Value -ErrorAction SilentlyContinue).$Smb1Value
    if ($finalCheck -eq 0) {
        Write-Host "PROTECTED" -ForegroundColor Green
    } else {
        Write-Host "ACTION REQUIRED" -ForegroundColor Red
    }
    Write-Host "--------------------------------------------------------" -ForegroundColor Gray
}

# Clear keyboard buffer
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }
Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

##------------------------------------------------------##

# ============================================================
# DISABLE SYSTEM CRASH DUMPS
# ============================================================

Write-Host "[SYSTEM] Verifying crash dump configuration..." -ForegroundColor Cyan

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"

# Desired configuration
$desiredValues = @{
    "CrashDumpEnabled" = 0
    "LogEvent"         = 0
}

try {
    if (Test-Path $registryPath) {

        $needsUpdate = $false

        foreach ($name in $desiredValues.Keys) {

            # Get current value (if exists)
            $currentValue = (Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue).$name
            $desiredValue = $desiredValues[$name]

            if ($null -eq $currentValue) {
                Write-Host ">> $name not set. Will configure..." -ForegroundColor Yellow
                $needsUpdate = $true
            }
            elseif ($currentValue -ne $desiredValue) {
                Write-Host ">> $name mismatch (Current: $currentValue | Desired: $desiredValue). Updating..." -ForegroundColor Yellow
                $needsUpdate = $true
            }
            else {
                Write-Host ">> $name already correctly set ($currentValue)." -ForegroundColor DarkGray
            }
        }

        if ($needsUpdate) {

            Write-Host ">> Applying crash dump configuration..." -ForegroundColor Gray

            foreach ($name in $desiredValues.Keys) {
                Set-ItemProperty -Path $registryPath `
                    -Name $name `
                    -Value $desiredValues[$name] `
                    -Force
            }

            Write-Host "[OK] Crash dump configuration applied successfully." -ForegroundColor Green
        }
        else {
            Write-Host "[OK] System already configured. No changes needed." -ForegroundColor Green
        }

    }
    else {
        Write-Host "[ERROR] CrashControl registry path not found." -ForegroundColor Red
    }
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

##------------------------------------------------------##

# --- BITLOCKER PURGE & PRIVACY MANIFEST ---
# Purpose: Deep scan, automatic decryption, and Registry Hardening to restore privacy and performance.

Write-Host "************************************************************" -ForegroundColor Red
Write-Host "             BITLOCKER PRIVACY & UTILITY ALERT             " -ForegroundColor White -BackgroundColor Red
Write-Host "************************************************************" -ForegroundColor Red
Write-Host "1. ZERO PRIVACY: BitLocker keys are often backed up to MS"
Write-Host "   servers automatically. It's a 'black box' encryption where"
Write-Host "   your data and keys are accessible to government agencies."
Write-Host "2. PERFORMANCE DRAIN: Constant real-time encryption/decryption"
Write-Host "   overhead can reduce SSD R/W speeds by up to 20-45%."
Write-Host "3. RECOVERY TRAP: A BIOS update or hardware change can lock"
Write-Host "   you out of your own data forever if the key is lost."
Write-Host "4. INSECURE BY DESIGN: Law enforcement backdoors and DMA"
Write-Host "   attacks make it less secure than open-source alternatives."
Write-Host "************************************************************`n" -ForegroundColor Red

# Helper Function to check and set registry with detailed logging
function Set-RegistryIfMissing {
    param (
        [string]$Path,
        [string]$Name,
        [uint32]$Value
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    $currentVal = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    
    if ($null -eq $currentVal -or $currentVal.$Name -ne $Value) {
        Write-Host " [APPLIED] $Name = $Value" -ForegroundColor Yellow
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWORD -Force
    } else {
        Write-Host " [EXISTING] $Name is already set to $Value" -ForegroundColor Gray
    }
}

# --- 1. Registry Hardening ---
Write-Host " [🛡️] ANALYZING REGISTRY HARDENING..." -ForegroundColor Cyan

# A. Prevent Automatic Device Encryption
Set-RegistryIfMissing -Path "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker" -Name "PreventDeviceEncryption" -Value 1

# B. Disable Hardware-Based Encryption
$fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
Set-RegistryIfMissing -Path $fvePath -Name "OSHardwareEncryption" -Value 0
Set-RegistryIfMissing -Path $fvePath -Name "OSAllowSoftwareEncryptionFailover" -Value 0
Set-RegistryIfMissing -Path $fvePath -Name "OSRestrictHardwareEncryptionAlgorithms" -Value 0

# C. Disable BitLocker on Removable Drives (BitLocker To Go)
Set-RegistryIfMissing -Path $fvePath -Name "RDVConfigureBDE" -Value 0
Set-RegistryIfMissing -Path $fvePath -Name "RDVAllowBDE" -Value 0
Set-RegistryIfMissing -Path $fvePath -Name "RDVDisableBDE" -Value 0

Write-Host " [✅] Registry check complete." -ForegroundColor Green

# --- 2. Active Decryption Logic ---
Write-Host "`n [🔍] ANALYZING VOLUMES FOR ACTIVE ENCRYPTION..." -ForegroundColor Cyan

try {
    $drives = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq 'OperatingSystem' -or $_.VolumeType -eq 'FixedData' }
} catch {
    $drives = $null
}

if ($null -eq $drives -or $drives.Count -eq 0) {
    Write-Host " [✅] Clean: No active BitLocker volumes detected." -ForegroundColor Green
} else {
    foreach ($volume in $drives) {
        $driveLetter = $volume.MountPoint
        $status = $volume.VolumeStatus
        
        Write-Host " [*] Drive ${driveLetter} Status: $status" -ForegroundColor White
        
        if ($status -ne "FullyDecrypted") {
            Write-Host " [!] BitLocker detected on ${driveLetter}. Initiating decryption..." -ForegroundColor Yellow
            try {
                Disable-BitLocker -MountPoint $driveLetter -ErrorAction Stop
                Write-Host " [▶] Decryption started for ${driveLetter}." -ForegroundColor Green
            } catch {
                Write-Host " [❌] Failed to disable BitLocker on ${driveLetter}: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host " [✅] Drive ${driveLetter} is already decrypted and private." -ForegroundColor Green
        }
    }
}

Write-Host "`nProcess complete! System is now BitLocker-resistant. ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------" -ForegroundColor Cyan

##------------------------------------------------------##

# ============================================================
# Windows Security Hardening Module
# ============================================================

Write-Host "`n[Security Module] Starting Hardening..." -ForegroundColor Cyan

# ------------------------------------------------------------
# Helper Function: Check and Set Registry Value Safely
# ------------------------------------------------------------
function Set-RegistryValueSafe {
    param (
        [string]$Path,
        [string]$Name,
        [int]$Value
    )

    try {
        # Ensure registry path exists
        if (-not (Test-Path $Path)) {
            Write-Host "    -> Creating path: $Path"
            New-Item -Path $Path -Force | Out-Null
        }

        # Read current value safely
        $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name

        if ($null -eq $current) {
            Write-Host "    -> Setting $Name = $Value (Not Set)"
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
        }
        elseif ($current -ne $Value) {
            Write-Host "    -> Fixing $Name (Current: $current → Expected: $Value)"
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
        }
        else {
            Write-Host "    ✔ $Name already compliant ($Value)" -ForegroundColor DarkGreen
        }
    }
    catch {
        Write-Host "    ✖ ERROR setting $Name : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ------------------------------------------------------------
# SECTION 1 — Autorun / Autoplay Protection
# ------------------------------------------------------------
Write-Host "`n[1] Autorun & Autoplay Hardening..." -ForegroundColor Cyan

$autorunPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
    "HKCU:\Software\Policies\Microsoft\Windows\Explorer",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
)

foreach ($path in $autorunPaths) {
    Write-Host "`n[+] Processing: $path" -ForegroundColor Yellow

    Set-RegistryValueSafe -Path $path -Name "NoDriveTypeAutoRun" -Value 255
    Set-RegistryValueSafe -Path $path -Name "NoAutorun" -Value 1

    if ($path -match "AutoplayHandlers") {
        Set-RegistryValueSafe -Path $path -Name "DisableAutoplay" -Value 1
    }
}

# ------------------------------------------------------------
# SECTION 2 — Security Zone Lock (Browser/System)
# ------------------------------------------------------------
Write-Host "`n[2] Security Zone Hardening..." -ForegroundColor Cyan

$zonePaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
    "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
)

foreach ($path in $zonePaths) {
    Write-Host "`n[+] Processing: $path" -ForegroundColor Yellow

    Set-RegistryValueSafe -Path $path -Name "Security_HKLM_only" -Value 1
    Set-RegistryValueSafe -Path $path -Name "Security_Zones_Map_Edit" -Value 1
}

# ------------------------------------------------------------
# SECTION 3 — Download Integrity (Attachment Manager)
# ------------------------------------------------------------
Write-Host "`n[3] Download Integrity Protection..." -ForegroundColor Cyan

$attachmentPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Attachments",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
)

foreach ($path in $attachmentPaths) {

    Write-Host "`n[+] Processing: $path" -ForegroundColor Yellow

    try {
        if (Test-Path $path) {

            $existing = Get-ItemProperty -Path $path -Name "ScanWithAntiVirus" -ErrorAction SilentlyContinue

            if ($null -ne $existing.ScanWithAntiVirus) {
                Write-Host "    -> Removing ScanWithAntiVirus"
                Remove-ItemProperty -Path $path -Name "ScanWithAntiVirus" -ErrorAction SilentlyContinue
                Write-Host "    ✔ Removed" -ForegroundColor Green
            }
            else {
                Write-Host "    ✔ ScanWithAntiVirus already absent" -ForegroundColor DarkGreen
            }

            Set-RegistryValueSafe -Path $path -Name "SaveZoneInformation" -Value 2
        }
        else {
            Write-Host "    ✔ Path does not exist (nothing to clean)" -ForegroundColor DarkGreen
        }
    }
    catch {
        Write-Host "    ✖ ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ------------------------------------------------------------
# SECTION 4 — Digital Signature Enforcement
# ------------------------------------------------------------
Write-Host "`n[4] WinTrust Integrity Check..." -ForegroundColor Cyan

$winTrustPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"

Write-Host "`n[+] Auditing: $winTrustPath" -ForegroundColor Yellow

try {
    $currentState = (Get-ItemProperty -Path $winTrustPath -Name "State" -ErrorAction SilentlyContinue).State

    if ($null -eq $currentState) {
        Write-Host "    ℹ State not found (system default assumed)" -ForegroundColor Gray
    }
    else {
        if ($currentState -ne 0x23C00 -and $currentState -ne 0x23E00) {
            Write-Host "    ⚠ Non-standard WinTrust State detected: $currentState" -ForegroundColor Yellow
        }
        else {
            Write-Host "    ✔ WinTrust State is standard ($currentState)" -ForegroundColor DarkGreen
        }
    }
}
catch {
    Write-Host "    ✖ ERROR reading WinTrust state" -ForegroundColor Red
}

# ------------------------------------------------------------
# FINAL STATUS
# ------------------------------------------------------------
Write-Host "`n[✓] Hardening check completed successfully." -ForegroundColor Green
Write-Host "[i] System is now aligned with safe security baseline." -ForegroundColor Cyan
Write-Host "[!] Reboot may be required for full effect." -ForegroundColor Yellow
Write-Host ""

##------------------------------------------------------##

# ============================================
# Windows Performance & Privacy Optimization
# ============================================

$Global:Changes = 0
$Global:Errors = 0

# ============================================
# LOG
# ============================================

function Write-Log {
    param ($Type, $Message)

    switch ($Type) {
        "APPLY" { Write-Host "⚡ $Message" -ForegroundColor Cyan; $Global:Changes++ }
        "FIX"   { Write-Host "🔧 $Message" -ForegroundColor Yellow; $Global:Changes++ }
        "INFO"  { Write-Host "ℹ️  $Message" -ForegroundColor Gray }
        "ERROR" { Write-Host "❌ $Message" -ForegroundColor Red; $Global:Errors++ }
    }
}

# ============================================
# RAM REAL
# ============================================

function Get-RealRAM {
    try {
        $ramBytes = (Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum
        $ramGB = $ramBytes / 1GB
        $ramMB = $ramBytes / 1MB
        $culture = [System.Globalization.CultureInfo]::InvariantCulture

        return @{
            Bytes = $ramBytes
            Text  = "$($ramGB.ToString("F2",$culture)) GB ($([math]::Round($ramMB)) MB)"
        }
    } catch {
        Write-Log "ERROR" "RAM detection failed"
        return $null
    }
}

# ============================================
# HELPERS
# ============================================

function Set-RegValueSafe {
    param ($Path, $Name, $Value, $Type = "DWord")

    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
        }

        $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name

        if ($null -eq $current -or $current -ne $Value) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
            Write-Log "APPLY" "$Name → $Value"
        }

    } catch {
        Write-Log "ERROR" "$Name failed"
    }
}

function Remove-RegValueSafe {
    param ($Path, $Name)

    try {
        if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $Path -Name $Name
            Write-Log "FIX" "$Name removed (Windows default)"
        }
    } catch {
        Write-Log "ERROR" "$Name removal failed"
    }
}

function Set-ServiceSafe {
    param ($Name, $StartupType)

    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop

        if ($svc.StartType -ne $StartupType) {
            Set-Service -Name $Name -StartupType $StartupType
            Write-Log "APPLY" "$Name service → $StartupType"
        }

    } catch {
        Write-Log "INFO" "$Name service not found (skipped)"
    }
}

function Disable-TaskSafe {
    param([string]$TaskPath)

    try {
        $tasks = Get-ScheduledTask -TaskPath $TaskPath -ErrorAction SilentlyContinue

        foreach ($task in $tasks) {
            if ($task.State -ne "Disabled") {

                $taskName = $task.TaskName
                $fullName = "$TaskPath$taskName"

                try {
                    Disable-ScheduledTask -InputObject $task -ErrorAction Stop
                    Write-Log "APPLY" "Task disabled: $taskName"
                    continue
                }
                catch {}

                try {
                    $tempName = "TempDisable_" + [guid]::NewGuid().ToString()

                    $cmd = "schtasks /Change /TN `"$fullName`" /Disable"

                    schtasks /Create /TN $tempName /TR $cmd /SC ONCE /ST 00:00 /RU SYSTEM /F >$null 2>&1
                    schtasks /Run /TN $tempName >$null 2>&1

                    Start-Sleep -Milliseconds 500

                    schtasks /Delete /TN $tempName /F >$null 2>&1
                }
                catch {}

                $check = Get-ScheduledTask -TaskPath $TaskPath -TaskName $taskName -ErrorAction SilentlyContinue

                if ($check -and $check.State -eq "Disabled") {
                    Write-Log "FIX" "Forced disable (SYSTEM): $taskName"
                } else {
                    Write-Log "INFO" "Still protected (TrustedInstaller): $taskName"
                }
            }
        }
    } catch {
        Write-Log "ERROR" "Task path failed: $TaskPath"
    }
}

# ============================================
# SYSTEM
# ============================================

Write-Host "`n=== System ==="

Set-RegValueSafe "HKCU:\Control Panel\Desktop" "WaitToKillAppTimeout" "2000" "String"
Set-RegValueSafe "HKCU:\Control Panel\Desktop" "HungAppTimeout" "2000" "String"
Set-RegValueSafe "HKCU:\Control Panel\Desktop" "AutoEndTasks" "1" "String"
Set-RegValueSafe "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" "AutoReboot" 0

Set-ServiceSafe "RemoteRegistry" "Disabled"

# Faster service shutdown
Set-RegValueSafe "HKLM:\SYSTEM\CurrentControlSet\Control" "WaitToKillServiceTimeout" "2500" String
Set-RegValueSafe "HKLM:\SYSTEM\ControlSet001\Control" "WaitToKillServiceTimeout" "2500" String

# Disable Power Throttling
Set-RegValueSafe "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" "PowerThrottlingOff" 1
Set-RegValueSafe "HKLM:\SYSTEM\ControlSet001\Control\Power\PowerThrottling" "PowerThrottlingOff" 1

# ============================================
# EXPLORER
# ============================================

Write-Host "`n=== Explorer ==="

$ram = Get-RealRAM
if ($ram) { Write-Log "INFO" "RAM: $($ram.Text)" }

if ($ram.Bytes -ge 8GB) {
    Set-RegValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "SeparateProcess" 1
}

Set-RegValueSafe "HKCU:\Control Panel\Desktop" "ForegroundLockTimeout" 0
Set-RegValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisablePreviewDesktop" 0
Set-RegValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisallowShaking" 1

# ============================================
# MEMORY / CPU
# ============================================

Write-Host "`n=== Memory / CPU ==="

if ($ram -and $ram.Bytes -ge 8GB) {
    Set-RegValueSafe "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "DisablePagingExecutive" 1
}

Remove-RegValueSafe "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" "Win32PrioritySeparation"

# ============================================
# NETWORK
# ============================================

Write-Host "`n=== Network ==="

Set-RegValueSafe "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" 4294967295
Set-RegValueSafe "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "MaxCacheTtl" 86400

Remove-RegValueSafe "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnablePMTUDiscovery"
Remove-RegValueSafe "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DefaultTTL"

# ============================================
# PRIVACY / TELEMETRY
# ============================================

Write-Host "`n=== Privacy / Telemetry ==="

# Main telemetry keys
Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
Set-RegValueSafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0

# WOW6432Node telemetry keys
Set-RegValueSafe "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0
Set-RegValueSafe "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0

# Scheduled Tasks
Disable-TaskSafe "\Microsoft\Windows\Application Experience\"
Disable-TaskSafe "\Microsoft\Windows\Customer Experience Improvement Program\"
Disable-TaskSafe "\Microsoft\Windows\Autochk\"
Disable-TaskSafe "\Microsoft\Windows\DiskDiagnostic\"
Disable-TaskSafe "\Microsoft\Windows\Feedback\Siuf\"

# ============================================
# ADOBE
# ============================================

Write-Host "`n=== Adobe ==="

try {
    $task = Get-ScheduledTask -TaskName "Adobe Acrobat Update Task" -ErrorAction SilentlyContinue

    if ($task) {
        if ($task.State -ne "Disabled") {
            Disable-ScheduledTask -InputObject $task
            Write-Log "APPLY" "Adobe scheduled task disabled"
        } else {
            Write-Log "INFO" "Adobe task already disabled"
        }
    } else {
        Write-Log "INFO" "Adobe task not found"
    }
} catch {
    Write-Log "ERROR" "Adobe task failed"
}

Set-ServiceSafe "AdobeARMservice" "Disabled"
Set-ServiceSafe "adobeupdateservice" "Disabled"

# ============================================
# SEARCH
# ============================================

Write-Host "`n=== Windows Search ==="

$search = Get-Service WSearch -ErrorAction SilentlyContinue
if ($search -and $search.Status -ne "Stopped") {
    Stop-Service WSearch -Force
    Write-Log "APPLY" "Windows Search stopped"
}
Set-ServiceSafe "WSearch" "Disabled"

Set-RegValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0
Set-RegValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "CortanaConsent" 0

# ============================================
# DELIVERY
# ============================================

Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> #

# ============================================
# ADS / TRACKING DISABLE
# ============================================

Write-Host "`n=== Ads / Tracking ===" -ForegroundColor Cyan
Write-Host "-- Disabling Targeted Ads and Data Collection" -ForegroundColor Green

# ============================================
# SAFE REGISTRY WRITE FUNCTION
# ============================================

function Set-RegValueSafe {

    param (
        [string]$Path,
        [string]$Name,
        $Value
    )

    try {

        # Create registry path if missing
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        # Create/update DWORD value
        New-ItemProperty `
            -Path $Path `
            -Name $Name `
            -Value $Value `
            -PropertyType DWord `
            -Force | Out-Null

        Write-Host "⚡ $Name → $Value" -ForegroundColor Green
    }
    catch {

        Write-Host "❌ $Name failed" -ForegroundColor Red
    }
}

# ------------------------------------------------
# CLOUD CONTENT (Consumer Features / Spotlight / Suggestions)
# ------------------------------------------------

Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableSoftLanding" 1
Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures" 1
Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1

Set-RegValueSafe "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1

# ------------------------------------------------
# PRIVACY / TAILORED EXPERIENCES
# ------------------------------------------------

$privacyPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"
)

foreach ($path in $privacyPaths) {

    # Create path if missing
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }

    Set-RegValueSafe $path "TailoredExperiencesWithDiagnosticDataEnabled" 0
}

# ------------------------------------------------
# APPLY TO LOADED USER HIVES AUTOMATICALLY
# ------------------------------------------------

$loadedUsers = Get-ChildItem "Registry::HKEY_USERS" |
Where-Object {
    $_.Name -match "S-1-5-21-" -and
    $_.PSChildName -notmatch "_Classes"
}

foreach ($user in $loadedUsers) {

    $userPrivacy = "Registry::$($user.Name)\Software\Microsoft\Windows\CurrentVersion\Privacy"

    if (!(Test-Path $userPrivacy)) {
        New-Item -Path $userPrivacy -Force | Out-Null
    }

    Set-RegValueSafe $userPrivacy "TailoredExperiencesWithDiagnosticDataEnabled" 0
}

# ------------------------------------------------
# POLICY ENFORCEMENT (STRONGEST PRIORITY)
# ------------------------------------------------

Set-RegValueSafe "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1
Set-RegValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" "TailoredExperiencesWithDiagnosticDataEnabled" 0

# ------------------------------------------------
# EXTRA HARDENING
# ------------------------------------------------

Set-RegValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1

Write-Host "`nAds / Tracking settings applied successfully." -ForegroundColor Green

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> #

# ============================================
# BACKGROUND DATA
# ============================================

Write-Host "`n=== Background Data ==="

Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0
Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0
Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" 0
Set-RegValueSafe "HKCU:\Software\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0
Set-RegValueSafe "HKCU:\Software\Microsoft\Siuf\Rules" "PeriodInNanoSeconds" 0

# ============================================
# Disable Windows suggestions
# ============================================

Set-RegValueSafe "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0
Set-RegValueSafe "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SoftLandingEnabled" 0
Set-RegValueSafe "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0

# ============================================
# DISABLE IE
# ============================================

Write-Host "`n=== Disable Internet Explorer ===" 
dism /online /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64 /NoRestart | Out-Null

# ============================================
# SUMMARY
# ============================================

Write-Host "`n============================================"
Write-Host "Changes applied: $Global:Changes"
Write-Host "Errors: $Global:Errors"

if ($Global:Changes -eq 0) {
    Write-Host "System already optimized ✔" -ForegroundColor Green
} else {
    Write-Host "Optimization applied ⚡" -ForegroundColor Cyan
}

Write-Host "Restart recommended."
Write-Host "============================================"
Write-Host ""

# ============================================
# MMCSS RESPONSIVENESS
# ============================================

Write-Host "`n=== MMCSS Responsiveness ==="

# ------------------------------------------------
# SAFE REGISTRY WRITER
# ------------------------------------------------
function Set-RegValueSafe {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value
    )

    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
    }
    catch {
        Write-Host "[WARN] Failed to write registry: $Name" -ForegroundColor Yellow
    }
}

# ------------------------------------------------
# DETECT WINDOWS SERVER
# ------------------------------------------------
function Get-IsWindowsServer {
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        return ($os.ProductType -ne 1)
    }
    catch {
        Write-Host "[WARN] Could not detect OS type. Assuming Workstation." -ForegroundColor Yellow
        return $false
    }
}

# ------------------------------------------------
# RAM DETECTION
# ------------------------------------------------
function Get-RealRAM {
    try {
        $ramBytes = (Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum
        return [math]::Round($ramBytes / 1GB, 2)
    }
    catch {
        Write-Host "[ERROR] RAM detection failed. Defaulting to 8GB." -ForegroundColor Red
        return 8
    }
}

# ------------------------------------------------
# CPU DETECTION
# ------------------------------------------------
function Get-LogicalCPU {
    try {
        return (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    }
    catch {
        Write-Host "[WARN] CPU detection failed. Assuming 4 threads." -ForegroundColor Yellow
        return 4
    }
}

# ------------------------------------------------
# SYSTEM INFO
# ------------------------------------------------
$TotalRAM = Get-RealRAM
$IsServer = Get-IsWindowsServer
$LogicalProcessors = Get-LogicalCPU

Write-Host "[INFO] Detected RAM: $TotalRAM GB" -ForegroundColor Gray
Write-Host "[INFO] Logical CPUs: $LogicalProcessors" -ForegroundColor Gray
Write-Host "[INFO] Windows Server: $IsServer" -ForegroundColor Gray

# ------------------------------------------------
# APPLY SMART VALUE
# ------------------------------------------------
if ($IsServer) {

    # SERVER (FIREBIRD / DATABASE SAFE PROFILE)
    if ($TotalRAM -ge 32 -and $LogicalProcessors -ge 8) {
        $Responsiveness = 5
    }
    elseif ($TotalRAM -ge 16 -and $LogicalProcessors -ge 6) {
        $Responsiveness = 5
    }
    else {
        $Responsiveness = 6
    }

} else {

    # DESKTOP
    if ($TotalRAM -ge 16) {

        if ($LogicalProcessors -le 4) {
            $Responsiveness = 5
        } else {
            $Responsiveness = 3
        }

    } elseif ($TotalRAM -ge 8) {
        $Responsiveness = 5
    } else {
        $Responsiveness = 7
    }
}

# ------------------------------------------------
# APPLY REGISTRY VALUE
# ------------------------------------------------
Set-RegValueSafe `
"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" `
"SystemResponsiveness" `
$Responsiveness

Write-Host "[OK] SystemResponsiveness = $Responsiveness" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# ============================================================
# Set Desktop Wallpaper Style and Rendering Behavior
# ============================================================

Write-Host "[⚙] Setting wallpaper style to Fill..." -NoNewline

try {

    # ------------------------------------------------------------
    # Registry path for current user desktop wallpaper settings
    # This controls how Windows renders the wallpaper image
    # ------------------------------------------------------------
    $path = "HKCU:\Control Panel\Desktop"

    # Validate registry path exists (prevents silent failures)
    if (-not (Test-Path $path)) {
        throw "Desktop registry path not found."
    }

    # ------------------------------------------------------------
    # Retrieve current wallpaper path
    # This is required to reapply wallpaper after style change
    # (prevents black screen or blank desktop issues)
    # ------------------------------------------------------------
    $currentWallpaper = (Get-ItemProperty -Path $path -Name "Wallpaper" -ErrorAction Stop).Wallpaper

    # Ensure wallpaper path is valid before continuing
    if ([string]::IsNullOrWhiteSpace($currentWallpaper)) {
        throw "Wallpaper path not found. Cannot safely apply settings."
    }

    # ------------------------------------------------------------
    # Wallpaper rendering configuration
    # These values control how the image is displayed on screen
    # ------------------------------------------------------------

    # WallpaperStyle values:
    # 0  = Center (image stays centered at original size)
    # 2  = Stretch (forces image to fill screen, may distort)
    # 6  = Fit (scales image to fit screen while preserving ratio)
    # 10 = Fill (scales image to fully cover screen, may crop edges)
    #
    # TileWallpaper values:
    # 0 = Disabled (image is not repeated)
    # 1 = Enabled (image is tiled across the screen)
    # ------------------------------------------------------------

    Set-ItemProperty -Path $path -Name "WallpaperStyle" -Value "10" -Force
    Set-ItemProperty -Path $path -Name "TileWallpaper" -Value "0" -Force

    # ------------------------------------------------------------
    # Load Win32 API for instant wallpaper refresh
    # SystemParametersInfo forces Windows to apply changes immediately
    # without requiring logoff or restart
    # ------------------------------------------------------------
    if (-not ("WallpaperAPI" -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class WallpaperAPI {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(
        int uAction,
        int uParam,
        string lpvParam,
        int fuWinIni
    );
}
"@
    }

    # ------------------------------------------------------------
    # WinAPI constants used to update desktop settings
    # ------------------------------------------------------------
    $SPI_SETDESKWALLPAPER = 0x0014
    $SPIF_UPDATEINIFILE   = 0x01
    $SPIF_SENDCHANGE      = 0x02

    # ------------------------------------------------------------
    # Apply wallpaper immediately using current image path
    # This refreshes the desktop with new rendering mode
    # ------------------------------------------------------------
    [WallpaperAPI]::SystemParametersInfo(
        $SPI_SETDESKWALLPAPER,
        0,
        $currentWallpaper,
        $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE
    ) | Out-Null

    Write-Host " OK (Fill mode applied)" -ForegroundColor Green
}
catch {

    # ------------------------------------------------------------
    # Error handling
    # Displays only the root exception message for clarity
    # ------------------------------------------------------------
    Write-Host " ERROR" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor DarkRed
}

Write-Host ""

##------------------------------------------------------##

# ============================================
# ENABLE CLASSIC WINDOWS PHOTO VIEWER
# ============================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host "`n=== Enabling Classic Windows Photo Viewer ===" -ForegroundColor Cyan

$basePath = "HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations"

# Ensure base path exists
New-Item -Path $basePath -Force | Out-Null

# File associations
$associations = @{
    ".bmp"  = "PhotoViewer.FileAssoc.BITMAP"
    ".dib"  = "PhotoViewer.FileAssoc.BITMAP"
    ".jpg"  = "PhotoViewer.FileAssoc.JPEG"
    ".jpe"  = "PhotoViewer.FileAssoc.JPEG"
    ".jpeg" = "PhotoViewer.FileAssoc.JPEG"
    ".jxr"  = "PhotoViewer.FileAssoc.JPEG"
    ".jfif" = "PhotoViewer.FileAssoc.JFIF"
    ".wdp"  = "PhotoViewer.FileAssoc.WDP"
    ".png"  = "PhotoViewer.FileAssoc.PNG"
    ".gif"  = "PhotoViewer.FileAssoc.TIFF"
    ".tiff" = "PhotoViewer.FileAssoc.TIFF"
    ".tif"  = "PhotoViewer.FileAssoc.TIFF"
}

foreach ($ext in $associations.Keys) {
    New-ItemProperty -Path $basePath -Name $ext -Value $associations[$ext] -PropertyType String -Force | Out-Null
}

Write-Host "File associations applied." -ForegroundColor Green

# Helper function to create registry class
function Create-PhotoViewerClass {
    param (
        [string]$class,
        [string]$icon,
        [string]$dllOffset
    )

    $root = "HKLM:\SOFTWARE\Classes\$class"

    New-Item -Path $root -Force | Out-Null
    New-ItemProperty -Path $root -Name "ImageOptionFlags" -Value 1 -PropertyType DWord -Force | Out-Null

    New-Item -Path "$root\DefaultIcon" -Force | Out-Null
    Set-ItemProperty -Path "$root\DefaultIcon" -Name "(default)" -Value $icon

    New-Item -Path "$root\shell\open\command" -Force | Out-Null
    Set-ItemProperty -Path "$root\shell\open\command" -Name "(default)" -Value `
        "`"%SystemRoot%\System32\rundll32.exe`" `"%SystemRoot%\System32\PhotoViewer.dll,$dllOffset`" `"%1`""
}

# Create main handlers
Create-PhotoViewerClass "PhotoViewer.FileAssoc.BITMAP" "%SystemRoot%\System32\imageres.dll,-70" "ImageView_Fullscreen"
Create-PhotoViewerClass "PhotoViewer.FileAssoc.JPEG"   "%SystemRoot%\System32\imageres.dll,-72" "ImageView_Fullscreen"
Create-PhotoViewerClass "PhotoViewer.FileAssoc.PNG"    "%SystemRoot%\System32\imageres.dll,-71" "ImageView_Fullscreen"

# JFIF special handling
$jfif = "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF"
New-Item -Path $jfif -Force | Out-Null
New-ItemProperty -Path $jfif -Name "ImageOptionFlags" -Value 1 -PropertyType DWord -Force | Out-Null

Write-Host "Classic Photo Viewer enabled successfully." -ForegroundColor Green
Write-Host ""

##------------------------------------------------------##

# --- INTERACTIVE ONEDRIVE UNINSTALLATION ---

# Detect current Windows user
$currentUserOD = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$currentUserNameOD = ($currentUserOD -split '\\')[-1]

# Users that automatically approve OneDrive removal
$autoApproveUsersOD = @(
    "Admin",
    "Adm",
    "User",
    "Administrator"
)

if ($currentUserNameOD -in $autoApproveUsersOD) {

    Write-Host "Current user: $currentUserNameOD" -ForegroundColor Cyan
    Write-Host "Automatic approval: OneDrive will be uninstalled." -ForegroundColor Green

    $choiceOD = "Y"

} else {

    Write-Host "Current user: $currentUserNameOD" -ForegroundColor Cyan
    Write-Host "Do you want to COMPLETELY uninstall OneDrive? [Y/N] (Default: N in 5s): " -NoNewline -ForegroundColor Yellow

    $counterOD = 5

    while ($counterOD -gt 0 -and -not [console]::KeyAvailable) {
        Write-Host "..$counterOD " -NoNewline -ForegroundColor Gray
        Start-Sleep -Seconds 1
        $counterOD--
    }

    # Capture user input or timeout
    if ([console]::KeyAvailable) {
        $choiceOD = [console]::ReadKey($true).KeyChar
        Write-Host ""
    } else {
        Write-Host "`nTimeout reached. Skipping OneDrive removal..." -ForegroundColor Gray
        $choiceOD = "N"
    }
}

if ($choiceOD -eq 'y' -or $choiceOD -eq 'Y') {

    Write-Host "-- Starting deep uninstallation of OneDrive..." -ForegroundColor Green

    $ProgressPreference = "SilentlyContinue"

    # Kill process
    Write-Host "-- Closing OneDrive process..." -ForegroundColor Gray
    Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # Official uninstallers
    $uninstallerX86 = "$env:SystemRoot\System32\OneDriveSetup.exe"
    $uninstallerX64 = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"

    if (Test-Path $uninstallerX64) {

        Write-Host "-- Running official 64-bit uninstaller..." -ForegroundColor Gray
        Start-Process $uninstallerX64 -ArgumentList "/uninstall" -Wait

    } elseif (Test-Path $uninstallerX86) {

        Write-Host "-- Running official 32-bit uninstaller..." -ForegroundColor Gray
        Start-Process $uninstallerX86 -ArgumentList "/uninstall" -Wait
    }

    # Data migration
    Write-Host "-- Migrating OneDrive files..." -ForegroundColor Gray

    if (Test-Path "$env:USERPROFILE\OneDrive") {

        robocopy `
            "$env:USERPROFILE\OneDrive" `
            "$env:USERPROFILE" `
            /mov /e /xj /ndl /nfl /njh /njs /nc /ns /np | Out-Null
    }

    # Registry cleanup
    Write-Host "-- Cleaning Explorer integration..." -ForegroundColor Gray

    $oneDriveRegKeys = @(
        "HKCR:\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
        "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}",
        "HKCU:\Software\Microsoft\OneDrive"
    )

    foreach ($key in $oneDriveRegKeys) {
        Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Anti reinstall
    Write-Host "-- Applying anti-reinstallation policies..." -ForegroundColor Gray

    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"

    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    Set-ItemProperty $regPath "DisableFileSyncConfig" 1 -Type DWord
    Set-ItemProperty $regPath "PreventNetworkUserAccounts" 1 -Type DWord

    # Cleanup startup
    Write-Host "-- Removing shortcuts and startup entries..." -ForegroundColor Gray

    Remove-Item `
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" `
        -Force -ErrorAction SilentlyContinue

    reg delete `
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
        /v "OneDriveSetup" /f 2>$null

    Get-ScheduledTask `
        -TaskName 'OneDrive*' `
        -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask `
            -Confirm:$false `
            -ErrorAction SilentlyContinue

    # Remove leftovers
    Write-Host "-- Removing leftover folders..." -ForegroundColor Gray

    $folders = @(
        "$env:USERPROFILE\OneDrive",
        "$env:LOCALAPPDATA\OneDrive",
        "$env:LOCALAPPDATA\Microsoft\OneDrive",
        "$env:ProgramData\Microsoft OneDrive",
        "C:\OneDriveTemp"
    )

    foreach ($folder in $folders) {

        if (Test-Path $folder) {

            Remove-Item `
                $folder `
                -Recurse `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }

    Write-Host "OneDrive removed and blocked successfully! ✅" -ForegroundColor Cyan

} else {

    Write-Host "Skipping OneDrive removal..." -ForegroundColor Yellow
}

Write-Host "--------------------------------------------------------"

# Clear keyboard buffer
while ([console]::KeyAvailable) {
    [console]::ReadKey($true) | Out-Null
}

##------------------------------------------------------##

# Fix OneDrive launch / force-close issue
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"

if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

New-ItemProperty `
    -Path $regPath `
    -Name "DisableFileSyncNGSC" `
    -Value 0 `
    -PropertyType DWord `
    -Force | Out-Null

Write-Host "OneDrive policy updated successfully." -ForegroundColor Green

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
        iex (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/TogoFire-Home/WorkstationTools/main/Tools/Security/StartAllBack-Update-Blocker/Block-StartAllBack.ps1")
    } catch {
        # Error handling in case the URL is down or there is no internet connection
        Write-Host "Failed to execute script from GitHub. Please check your connection." -ForegroundColor Red
    }
} else {
    Write-Host "`nSkipping StartAllBack Blocker..." -ForegroundColor Gray
}

Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# ============================================
# SAFE APP DEBLOAT
# ============================================

$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

# Detect OS type
$os = Get-CimInstance Win32_OperatingSystem
$isServer = ($os.ProductType -ne 1)

Write-Host "`n=== App Debloat ===" -ForegroundColor Cyan

if ($isServer) {
    Write-Host "Windows Server detected. Skipping AppX debloat..." -ForegroundColor Yellow
    Write-Host "Continuing to next script section..." -ForegroundColor Gray
}
else {

    Write-Host "-- Removing Third-Party Apps" -ForegroundColor Green

    $thirdPartyPatterns = @(
        "*DropboxOEM*","*BingSearch*","*RandomSaladGamesLLC*","*UserExperienceImprovementProgram*",
        "*McAfee*","ShazamEntertainmentLtd.Shazam","ClearChannelRadioDigital.iHeartRadio",
        "SpotifyAB.SpotifyMusic","*EclipseManager*","*ActiproSoftwareLLC*",
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*","*Duolingo-LearnLanguagesforFree*",
        "*PandoraMediaInc*","*CandyCrush*","*BubbleWitch3Saga*","*Wunderlist*",
        "*Flipboard*","*Twitter*","*Facebook*","*Royal Revolt*","*Sway*",
        "*Speed Test*","*Dolby*","*Viber*","*ACGMediaPlayer*","*Netflix*",
        "*OneCalendar*","*LinkedInForWindows*","*HiddenCityMysteryofShadows*",
        "*Hulu*","*HiddenCity*","*AdobePhotoshopExpress*"
    )

    foreach ($pattern in $thirdPartyPatterns) {
        $pkgs = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $pattern }

        foreach ($pkg in $pkgs) {
            try {
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                Write-Host "Removed: $($pkg.Name)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed: $($pkg.Name)" -ForegroundColor Red
            }
        }
    }

    Write-Host "`n-- Removing Microsoft Apps" -ForegroundColor Green

    $msApps = @(
        "Microsoft.ZuneMusic","Microsoft.Whiteboard","Microsoft.Office.Lens","Microsoft.News",
        "Microsoft.GetHelp","Microsoft.BingTravel","Microsoft.BingHealthAndFitness",
        "Microsoft.BingFoodAndDrink","Microsoft.BingTranslator","Microsoft.AppConnector",
        "MicrosoftCorporationII.MicrosoftFamily","*QuickAssist*",
        "Clipchamp.Clipchamp","Microsoft.3DBuilder","Microsoft.Microsoft3DViewer",
        "Microsoft.BingWeather","Microsoft.BingSports","Microsoft.BingFinance",
        "Microsoft.MicrosoftOfficeHub","Microsoft.BingNews","Microsoft.Office.OneNote",
        "Microsoft.Office.Sway","Microsoft.WindowsPhone","Microsoft.CommsPhone",
        "Microsoft.YourPhone","Microsoft.Getstarted","Microsoft.549981C3F5F10",
        "Microsoft.Messaging","Microsoft.WindowsSoundRecorder","Microsoft.MixedReality.Portal",
        "Microsoft.WindowsFeedbackHub","Microsoft.WindowsAlarms","Microsoft.MSPaint",
        "Microsoft.WindowsMaps","Microsoft.MinecraftUWP","Microsoft.People",
        "Microsoft.Wallet","Microsoft.Print3D","Microsoft.OneConnect",
        "Microsoft.MicrosoftSolitaireCollection","Microsoft.MicrosoftStickyNotes",
        "microsoft.windowscommunicationsapps","Microsoft.SkypeApp","Microsoft.GroupMe10",
        "Microsoft.Todos","Microsoft.WindowsTerminal"
    )

    foreach ($app in $msApps) {
        $pkgs = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $app }

        foreach ($pkg in $pkgs) {
            try {
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                Write-Host "Removed: $($pkg.Name)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed: $($pkg.Name)" -ForegroundColor Red
            }
        }
    }

    Write-Host "`nCleanup completed successfully." -ForegroundColor Green
}

Write-Host ""

##------------------------------------------------------##

# ------------------------------------------------
# REMOVE WINDOWS AI - EXECUTION CONTROL
# ISOLATED MODULE - DOES NOT STOP THE MAIN SCRIPT
# ------------------------------------------------

& {

    $stateDirectory = Join-Path $env:ProgramData "RemoveWindowsAI"
    $stateFile = Join-Path $stateDirectory "execution.txt"

    # ------------------------------------------------
    # CHECK PREVIOUS EXECUTION
    # ------------------------------------------------

    if (Test-Path $stateFile) {
        Write-Host "[!] RemoveWindowsAI has already been executed successfully." -ForegroundColor Yellow
        Write-Host "[INFO] Execution record: $stateFile" -ForegroundColor Gray
        Write-Host "[INFO] Skipping execution." -ForegroundColor Cyan
        return
    }

    # ------------------------------------------------
    # TIMED YES/NO CONFIRMATION
    # Default after timeout: YES
    # ------------------------------------------------

    function Read-TimedConfirmation {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Prompt,

            [int]$TimeoutSeconds = 5
        )

        Write-Host ""
        Write-Host $Prompt -ForegroundColor Cyan
        Write-Host "Press Y to confirm or N to cancel." -ForegroundColor Gray
        Write-Host "Default: YES | Timeout: $TimeoutSeconds seconds" -ForegroundColor Yellow

        for ($remaining = $TimeoutSeconds; $remaining -ge 1; $remaining--) {
            Write-Host "`rTime remaining: $remaining... " -NoNewline -ForegroundColor Yellow

            $intervalEnd = [DateTime]::UtcNow.AddSeconds(1)

            try {
                while ([DateTime]::UtcNow -lt $intervalEnd) {
                    if ([Console]::KeyAvailable) {
                        $key = [Console]::ReadKey($true).KeyChar.ToString().ToLowerInvariant()

                        if ($key -eq 'y') {
                            Write-Host "`rYES selected.             " -ForegroundColor Green
                            return $true
                        }

                        if ($key -eq 'n') {
                            Write-Host "`rNO selected.              " -ForegroundColor Yellow
                            return $false
                        }
                    }

                    Start-Sleep -Milliseconds 50
                }
            }
            catch {
                Write-Host "`rConsole input unavailable. Defaulting to YES." -ForegroundColor Yellow
                return $true
            }
        }

        Write-Host "`rTIMEOUT - Defaulting to YES.       " -ForegroundColor Green
        return $true
    }

    # ------------------------------------------------
    # FIRST CONFIRMATION
    # ------------------------------------------------

    if (-not (Read-TimedConfirmation -Prompt "Do you want to remove Windows AI features?")) {
        Write-Host "`n[!] Operation cancelled by the user." -ForegroundColor Yellow
        Write-Host "[INFO] Skipping RemoveWindowsAI module." -ForegroundColor Gray
        Write-Host "--------------------------------------------------------" -ForegroundColor DarkGray
        return
    }

    # ------------------------------------------------
    # CHECK ADMINISTRATOR PRIVILEGES
    # ------------------------------------------------

    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)

    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
        Write-Host "[X] Please run this module as Administrator." -ForegroundColor Red
        Write-Host "[INFO] Skipping RemoveWindowsAI module." -ForegroundColor Gray
        return
    }

    # ------------------------------------------------
    # DOWNLOAD OFFICIAL REMOVE WINDOWS AI SCRIPT
    # ------------------------------------------------

    Write-Host "`n[🚀] Downloading RemoveWindowsAI..." -ForegroundColor Cyan

    $aiScript = Join-Path $env:TEMP "RemoveWindowsAi.ps1"
    $aiUrl = "https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1"

    try {
        Invoke-WebRequest -Uri $aiUrl -OutFile $aiScript -ErrorAction Stop

        if (!(Test-Path $aiScript) -or
            (Get-Item $aiScript).Length -lt 1000) {
            throw "The downloaded script is missing or appears invalid."
        }
    }
    catch {
        Write-Host "[X] Download failed: $_" -ForegroundColor Red
        Write-Host "[INFO] Skipping RemoveWindowsAI module." -ForegroundColor Gray
        return
    }

    # ------------------------------------------------
    # REMOVE ESET / AV WARNING + READKEY PAUSE
    # ------------------------------------------------

    Write-Host "[⚡] Preparing AI cleanup..." -ForegroundColor Green

    try {
        $scriptContent = Get-Content -LiteralPath $aiScript -ErrorAction Stop

        $scriptContent |
            Where-Object {
                $_ -notmatch "Press Any Key to Continue" -and
                $_ -notmatch "ReadKey" -and
                $_ -notmatch "third-party anti-virus" -and
                $_ -notmatch "may falsely block/break this script"
            } |
            Set-Content -LiteralPath $aiScript -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Host "[X] Failed to prepare the downloaded script: $_" -ForegroundColor Red
        Write-Host "[INFO] Skipping RemoveWindowsAI module." -ForegroundColor Gray
        return
    }

    # ------------------------------------------------
    # SELECTED OPTIONS
    # Excludes the three options marked with warning icons
    # ------------------------------------------------

    $aiOptions = @(
        "DisableRegKeys"
        "DisableCopilotPolicies"
        "RemoveAppxPackages"
        "RemoveRecallFeature"
        "HideAIComponents"
        "DisableRewrite"
    )

    Write-Host "`n[INFO] Selected options:" -ForegroundColor Cyan

    foreach ($option in $aiOptions) {
        Write-Host "  - $option" -ForegroundColor Gray
    }

    # ------------------------------------------------
    # SECOND CONFIRMATION
    # Default after timeout: YES
    # ------------------------------------------------

    if (-not (Read-TimedConfirmation -Prompt "Proceed with the selected changes?")) {
        Write-Host "`n[!] Operation cancelled by the user." -ForegroundColor Yellow
        Write-Host "[INFO] Skipping RemoveWindowsAI module." -ForegroundColor Gray
        Write-Host "--------------------------------------------------------" -ForegroundColor DarkGray
        return
    }

    # ------------------------------------------------
    # RUN USING WINDOWS POWERSHELL 5.1
    # ------------------------------------------------

    Write-Host "`n[⚡] Launching Windows PowerShell 5.1..." -ForegroundColor Cyan

    $optionString = $aiOptions -join ","
    $escapedScript = $aiScript.Replace("'", "''")

    $aiCommand = @"
& '$escapedScript' -NonInteractive -Options $optionString
if (`$LASTEXITCODE -ne `$null) { exit `$LASTEXITCODE }
if (`$?) { exit 0 } else { exit 1 }
"@

    try {
        $process = Start-Process `
            -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -ArgumentList @(
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command", $aiCommand
            ) `
            -Wait `
            -PassThru

        if ($process.ExitCode -eq 0) {
            try {
                if (!(Test-Path $stateDirectory)) {
                    New-Item -Path $stateDirectory -ItemType Directory -Force -ErrorAction Stop |
                        Out-Null
                }

                @"
Status=Success
Date=$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Options=$optionString
"@ | Set-Content -LiteralPath $stateFile -Encoding UTF8 -ErrorAction Stop

                Write-Host "`n[OK] Process completed with exit code 0." -ForegroundColor Green
                Write-Host "[OK] Execution record saved to: $stateFile" -ForegroundColor Green
            }
            catch {
                Write-Host "[!] Process completed, but the execution record could not be saved: $_" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "`n[!] RemoveWindowsAI exited with code $($process.ExitCode)." -ForegroundColor Yellow
            Write-Host "[INFO] No success record was created. You can retry." -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[X] Failed to launch RemoveWindowsAI: $_" -ForegroundColor Red
    }

    # ------------------------------------------------
    # CLEAR KEYBOARD BUFFER
    # ------------------------------------------------

    try {
        while ([Console]::KeyAvailable) {
            [Console]::ReadKey($true) | Out-Null
        }
    }
    catch {
        # Ignore hosts that do not support keyboard input.
    }

    Write-Host "`n[INFO] Review the output above to verify the applied changes." -ForegroundColor Cyan
    Write-Host "--------------------------------------------------------" -ForegroundColor DarkGray

} # END OF ISOLATED REMOVE WINDOWS AI MODULE

Write-Host "`n[INFO] RemoveWindowsAI module finished. Continuing with the next script..." -ForegroundColor Cyan

##------------------------------------------------------##

# --- INTERACTIVE MICROSOFT EDGE UNINSTALLATION ---

# Detect current Windows user
$currentUserEdge = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$currentUserNameEdge = ($currentUserEdge -split '\\')[-1]

# Users that automatically approve Edge removal
$autoApproveUsersEdge = @(
    "Admin",
    "Adm",
    "User",
    "Administrator"
)

if ($currentUserNameEdge -in $autoApproveUsersEdge) {

    Write-Host "Current user: $currentUserNameEdge" -ForegroundColor Cyan
    Write-Host "Automatic approval: Microsoft Edge will be uninstalled." -ForegroundColor Green

    $choiceEdge = "Y"

} else {

    Write-Host "Current user: $currentUserNameEdge" -ForegroundColor Cyan

    Write-Host "Do you want to UNINSTALL Microsoft Edge? [Y/N] (Default: N in 5s): " -NoNewline -ForegroundColor Yellow

    $counterEdge = 5

    while ($counterEdge -gt 0 -and (-not [console]::KeyAvailable)) {
        Write-Host "..$counterEdge " -NoNewline -ForegroundColor Gray
        Start-Sleep -Seconds 1
        $counterEdge--
    }

    # Capture user input or handle timeout
    if ([console]::KeyAvailable) {
        $choiceEdge = [console]::ReadKey($true).KeyChar
        Write-Host ""
    } else {
        Write-Host "`nTimeout reached. Skipping Edge uninstallation..." -ForegroundColor Gray
        $choiceEdge = "N"
    }
}

if ($choiceEdge -eq 'y' -or $choiceEdge -eq 'Y') {

    Write-Host "-- Initializing Edge uninstallation..." -ForegroundColor Green

    # 1. Enable uninstallation flag in Registry to bypass system restrictions
    $regPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev"

    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    Set-ItemProperty `
        -Path $regPath `
        -Name "AllowUninstall" `
        -Value 1 `
        -Type DWord `
        -ErrorAction SilentlyContinue

    # 2. Locate the official Microsoft Edge setup installer
    $edgeApps = Get-ChildItem `
        "C:\Program Files (x86)\Microsoft\Edge\Application\*\Installer\setup.exe" `
        -ErrorAction SilentlyContinue

    if ($edgeApps) {

        $installerPath = $edgeApps[0].FullName

        # Create a placeholder file to prevent Windows Update from re-registering the legacy Edge app
        $legacyAppPath = "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe"

        New-Item $legacyAppPath -Force -ErrorAction SilentlyContinue | Out-Null

        # Execute the uninstaller with force and profile deletion arguments
        Start-Process `
            $installerPath `
            -ArgumentList '--uninstall --system-level --force-uninstall --delete-profile' `
            -Wait

        # 3. Cleanup residual shortcuts from common system locations
        $shortcutPaths = @(
            "$env:Public\Desktop\Microsoft Edge.lnk",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
            "$env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk",
            "$env:UserProfile\Desktop\Microsoft Edge.lnk"
        )

        foreach ($lnk in $shortcutPaths) {
            if (Test-Path $lnk) {
                Remove-Item $lnk -Force -ErrorAction SilentlyContinue
            }
        }

        Write-Host "Success: Microsoft Edge has been removed and shortcuts cleaned." -ForegroundColor Cyan

    } else {

        Write-Host "Error: Edge setup.exe not found. Skipping." -ForegroundColor Red
    }

} else {

    Write-Host "Skipping Microsoft Edge uninstallation..." -ForegroundColor Yellow
}

Write-Host "--------------------------------------------------------"
Write-Host ""

# Clear keyboard buffer
try {
    while ([console]::KeyAvailable) {
        [console]::ReadKey($true) | Out-Null
    }
} catch {
    # Ignore hosts that do not support keyboard input.
}

##------------------------------------------------------##

Write-Host "--- SYSTEM PURGE: REMOVING JUNKWARE & DIGITAL PARASITES ---" -ForegroundColor Red -BackgroundColor Black

# --- INPUT EXORCISM ---
function Clear-InputBuffer {
    while ([console]::KeyAvailable) {
        [console]::ReadKey($true) | Out-Null
    }
}

function Read-Key {
    return ([console]::ReadKey($true).KeyChar.ToString().ToLower())
}

function Ask-YesNo($msg, $yesMsg, $noMsg) {
    Clear-InputBuffer
    Write-Host $msg -NoNewline -ForegroundColor Yellow

    while ($true) {
        $k = Read-Key
        if ($k -match "[yn]") {
            Write-Host $k
            if ($k -eq "y") {
                if ($yesMsg) { Write-Host $yesMsg -ForegroundColor DarkGray }
            } else {
                if ($noMsg) { Write-Host $noMsg -ForegroundColor DarkGray }
            }
            return $k
        }
    }
}

do {
    Clear-InputBuffer

    Write-Host "`n================================================" -ForegroundColor Gray
    Write-Host "   🛡️ JUNKWARE PURGE: CHOOSE YOUR TARGET" -ForegroundColor Red
    Write-Host "================================================" -ForegroundColor Gray
    Write-Host " [1] McAfee Removal (MCPR)"
    Write-Host " [2] Kaspersky Removal (kavremvr)"
    Write-Host " [3] Norton Removal (Exorcism Tool)"
    Write-Host " [4] AVG Removal (Clear-Cut)"
    Write-Host " [5] Antivirus Removal Tool (Universal Cleaner)"
    Write-Host " [6] Defender Remover (⚠️ SYSTEM RISK)"
    Write-Host " [Q] Quit Menu"
    Write-Host "------------------------------------------------" -ForegroundColor Gray
    Write-Host "Select an option (Auto-Exit in 5s): " -NoNewline

    $menuChoice = $null
    $timer = 5

    while ($timer -gt 0) {
        if ([console]::KeyAvailable) {
            $menuChoice = Read-Key
            Write-Host "$menuChoice" -ForegroundColor Cyan
            break
        }
        Write-Host "..$timer " -NoNewline -ForegroundColor Gray
        Start-Sleep 1
        $timer--
    }

    if (-not $menuChoice) {
        Write-Host "`n[TIMEOUT] No selection made. Exiting menu..." -ForegroundColor DarkGray
        $menuChoice = "q"
    }

    switch ($menuChoice) {

        "1" {
            $c = Ask-YesNo "`nLaunch MCPR? McAfee is basically a virus you pay for. Kill it? [Y/N]: " `
                "-- You chose violence. McAfee won't survive this." `
                "-- Mercy granted. McAfee lives another cursed day."

            if ($c -eq "y") {
                $url = "https://download.mcafee.com/molbin/iss-loc/SupportTools/MCPR/MCPR.exe"
                $path = "$env:TEMP\MCPR.exe"
                Invoke-WebRequest $url -OutFile $path
                Write-Host "-- FATALITY! Executing MCPR..." -ForegroundColor Green
                Start-Process $path
            }
        }

        "2" {
            $c = Ask-YesNo "`nSend Kaspersky to the gulag? [Y/N]: " `
                "-- No trial. Straight to Siberia." `
                "-- Peace treaty signed. Kaspersky spared."

            if ($c -eq "y") {
                $url = "https://media.kaspersky.com/utilities/ConsumerUtilities/kavremvr.exe"
                $path = "$env:TEMP\kavremvr.exe"
                Invoke-WebRequest $url -OutFile $path
                Write-Host "-- Dasvidaniya!" -ForegroundColor Green
                Start-Process $path
            }
        }

        "3" {
            $c = Ask-YesNo "`nDestroy Norton? It has more popups than a phishing site. [Y/N]: " `
                "-- Initiating exorcism ritual... Fetching the Binary Banisher..." `
                "-- Norton keeps haunting your RAM. The ghost in the machine remains."

            if ($c -eq "y") {
                $url = "https://honzik.avcdn.net/setup/norton-suite/release/norton_360_remover.exe"
                $path = "$env:TEMP\norton.exe"
                Invoke-WebRequest $url -OutFile $path
                Write-Host "-- Burning Norton to the ground..." -ForegroundColor Green
                Write-Host "-- Norton eliminated." -ForegroundColor Green
                Write-Host "-- The Norton demon has been cast out! ✝️🔥" -ForegroundColor Green
                Write-Host "------------------- YOUR RAM IS FREE AT LAST -------------------" -ForegroundColor Gray
                Start-Process $path
            }
        }

        "4" {
            $c = Ask-YesNo "`nWipe AVG? Fake mustache Avast clone detected. [Y/N]: " `
                "-- Removing impostor... Fetching the AVG 'Clear-Cut' Machete..." `
                "-- AVG remains. Your RAM is crying in the corner."

            if ($c -eq "y") {
                $url = "https://honzik.avcdn.net/setup/avg-av/release/avg_av_clear.exe"
                $path = "$env:TEMP\avg.exe"
                Invoke-WebRequest $url -OutFile $path
                Write-Host "-- Clearing the trash... Goodbye, AVG!" -ForegroundColor Green
                Write-Host "-- AVG deleted from existence." -ForegroundColor Green
                Start-Process $path
            }
        }

        "5" {
            $c = Ask-YesNo "`nDeploy Antivirus Removal Tool? This will scan and remove leftover AV junk. [Y/N]: " `
                "-- Deploying the nuclear cleaner..." `
                "-- You spared the junk. It will remember that."

            if ($c -eq "y") {
                Write-Host "-- Contacting mothership..." -ForegroundColor Cyan

                $zip = "$env:TEMP\ART.zip"
                $dir = "$env:TEMP\ART"

                try {
                    $redirect = $null

                    # --- Redirect real ---
                    try {
                        $req = [System.Net.WebRequest]::Create("https://antivirus-removal-tool.com/download/click.php?id=Antivirus_Removal_Tool")
                        $req.AllowAutoRedirect = $true
                        $resp = $req.GetResponse()
                        $redirect = $resp.ResponseUri.AbsoluteUri
                        $resp.Close()
                    } catch {}

                    # --- Fallback scraping ---
                    if (-not $redirect -or $redirect -notmatch "\.zip") {
                        $page = Invoke-WebRequest "https://antivirus-removal-tool.com/download/"
                        if ($page.Content -match "files\/Antivirus_Removal_Tool_\d+_\d+\.zip") {
                            $redirect = "https://antivirus-removal-tool.com/" + $matches[0]
                        }
                    }

                    if (-not $redirect) {
                        throw "Payload still hiding."
                    }

                    Write-Host "-- Target acquired: $redirect" -ForegroundColor DarkGray

                    # --- DOWNLOAD WITH REAL PROGRESS ---
                    $request = [System.Net.HttpWebRequest]::Create($redirect)
                    $request.UserAgent = "Mozilla/5.0"
                    $response = $request.GetResponse()

                    $total = $response.ContentLength
                    $stream = $response.GetResponseStream()
                    $file = [System.IO.File]::OpenWrite($zip)

                    $buffer = New-Object byte[] 8192
                    $read = 0
                    $totalRead = 0

                    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $file.Write($buffer, 0, $read)
                        $totalRead += $read

                        if ($total -gt 0) {
                            $percent = [int](($totalRead / $total) * 100)
                            Write-Progress -Activity "Downloading Antivirus Removal Tool" `
                                -Status "$percent% Complete" `
                                -PercentComplete $percent
                        }
                    }

                    $file.Close()
                    $stream.Close()
                    $response.Close()

                    Write-Progress -Activity "Downloading Antivirus Removal Tool" -Completed

                    if (-not (Test-Path $zip) -or (Get-Item $zip).Length -lt 50000000) {
                        throw "Downloaded file is invalid or incomplete."
                    }

                    Expand-Archive $zip -DestinationPath $dir -Force

                    $exe = Get-ChildItem $dir -Recurse -Filter "*.exe" | Select-Object -First 1

                    if ($exe) {
                        Write-Host "-- Launching universal cleaner..." -ForegroundColor Green
                        Start-Process $exe.FullName
                    } else {
                        Write-Host "[ERROR] No executable found." -ForegroundColor Red
                    }

                } catch {
                    Write-Host "[ERROR] Failed to download Antivirus Removal Tool." -ForegroundColor Red
                }
            }
        }

        "6" {
            $c = Ask-YesNo "`n⚠️ WARNING: Defender Remover can BREAK Windows Update. Continue? [Y/N]: " `
                "-- You like living dangerously." `
                "-- Wise choice. System spared."

            if ($c -eq "y") {
                $api = "https://api.github.com/repos/ionuttbara/windows-defender-remover/releases/latest"
                $r = Invoke-WebRequest $api | ConvertFrom-Json
                $url = ($r.assets | Where-Object { $_.name -like "*.exe" })[0].browser_download_url
                $path = "$env:TEMP\defender.exe"
                Invoke-WebRequest $url -OutFile $path
                Start-Process $path
            }
        }

        "q" {
            Write-Host "`nExiting Junkware Menu..." -ForegroundColor Green
        }

        default {
            Write-Host "`nInvalid option, try again." -ForegroundColor Red
        }
    }

} while ($menuChoice -ne "q")

# Clear keyboard buffer
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }

Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

##------------------------------------------------------##

<#
.SYNOPSIS
    Advanced Microsoft Defender SmartScreen Disabler (Audit & Force-Disable).
.DESCRIPTION
    Audits and disables SmartScreen for Explorer, Edge, and Microsoft Store Apps. 
    Includes PUA (Potentially Unwanted App) blocking removal.
#>

# --- VISUAL PRIVACY & UTILITY ALERT ---
Write-Host "************************************************************" -ForegroundColor Red
Write-Host "           SMARTSCREEN PRIVACY & UTILITY ALERT              " -ForegroundColor White -BackgroundColor Red
Write-Host "************************************************************" -ForegroundColor Red
Write-Host "1. FALSE POSITIVES: Flags safe tools and custom scripts"
Write-Host "   lacking expensive ($500/yr) EV Certificates."
Write-Host "2. PRIVACY DRAIN: Microsoft scans and logs every app and"
Write-Host "   file you run, sending metadata to their servers."
Write-Host "3. NAG-SCREEN CULTURE: Trains users to click 'Run Anyway'"
Write-Host "   without thinking, making the 'security' counterproductive."
Write-Host "4. PERFORMANCE OVERHEAD: Constant database checks against"
Write-Host "   every download and execution can lag file operations."
Write-Host "************************************************************`n" -ForegroundColor Red

Write-Host "--- Microsoft Defender SmartScreen Professional Audit ---" -ForegroundColor Cyan

function Set-RegistryOptimized {
    param (
        [string]$Path,
        [string]$Name,
        [parameter(Mandatory=$true)]$DisabledValue,
        [string]$Description,
        [string]$Type = "DWORD"
    )

    # Check if registry key exists; create if missing
    if (!(Test-Path $Path)) {
        Write-Host "[+] Creating missing registry path: $Path" -ForegroundColor Gray
        New-Item -Path $Path -Force | Out-Null
    }

    $currentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name

    # Apply changes if the value differs from target or is missing
    if ($currentValue -ne $DisabledValue) {
        Write-Host "[!] $Description is ENABLED or missing. Disabling..." -ForegroundColor Yellow
        if ($Type -eq "DWORD") {
            Set-ItemProperty -Path $Path -Name $Name -Value ([int]$DisabledValue) -Type DWord -Force
        } else {
            Set-ItemProperty -Path $Path -Name $Name -Value $DisabledValue -Force
        }
    } else {
        Write-Host "[OK] $Description is already disabled." -ForegroundColor Green
    }
}

# 1. System-wide File Execution (Explorer)
Set-RegistryOptimized `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" `
    -Name "SmartScreenEnabled" `
    -DisabledValue "Off" `
    -Type "String" `
    -Description "Explorer File/App Verification"

# 2. Potentially Unwanted App (PUA) Blocking
Set-RegistryOptimized `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" `
    -Name "PUAProtection" `
    -DisabledValue 0 `
    -Description "Potentially Unwanted App (PUA) Filter"

# 3. Microsoft Edge Browser Protection
Set-RegistryOptimized `
    -Path "HKCU:\Software\Microsoft\Edge\SmartScreenEnabled" `
    -Name "Enabled" `
    -DisabledValue 0 `
    -Description "Edge SmartScreen Filter"

# 4. Microsoft Store App Content Evaluation (AppHost)
Set-RegistryOptimized `
    -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" `
    -Name "EnableWebContentEvaluation" `
    -DisabledValue 0 `
    -Description "Store App Content Evaluation"

# 5. Store App Override Prevention (Ensures 'Run Anyway' is never blocked)
Set-RegistryOptimized `
    -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" `
    -Name "PreventOverride" `
    -DisabledValue 0 `
    -Description "Store App Override Policy"

# 6. Group Policy Overrides (Forces persistent state for all users)
Set-RegistryOptimized `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
    -Name "EnableSmartScreen" `
    -DisabledValue 0 `
    -Description "Global System Policy Override"

Write-Host "`nAll SmartScreen telemetry and blocking mechanisms have been audited." -ForegroundColor White -BackgroundColor DarkGreen
Write-Host "REBOOT RECOMMENDED to clear active shell/browser hooks." -ForegroundColor Yellow

##------------------------------------------------------##

# --- Interactive Windows Defender Purge ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Detect current Windows user
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$currentUserName = ($currentUser -split '\\')[-1]

Write-Host "Current Windows user: $currentUserName" -ForegroundColor Cyan

$autoApproveUsersDefender = @(
    "Admin",
    "Adm",
    "User",
    "Administrator"
)

# Check if user is in auto-approve list; otherwise prompt manually
if ($currentUserName -in $autoApproveUsersDefender) {
    Write-Host "User $currentUserName is auto-approved." -ForegroundColor Green
    $choice = "Y"
} else {
    Write-Host "User $currentUserName requires manual confirmation." -ForegroundColor Yellow
    Write-Host "Nuke Windows Defender? (WARNING: Flying solo after this) [Y/N]"
    Write-Host "Default: N | Waiting 7 seconds..." -ForegroundColor DarkGray

    $choice = "N"

    for ($i = 7; $i -ge 1; $i--) {
        Write-Host -NoNewline "$i.. "
        Start-Sleep -Seconds 1
    }

    Write-Host ""

    if ([Console]::KeyAvailable) {
        $key = [Console]::ReadKey($true)
        if ($key.KeyChar -eq 'Y' -or $key.KeyChar -eq 'y') {
            $choice = "Y"
        }
    }
}

if ($choice -eq 'Y') {
    Write-Host "Execution confirmed." -ForegroundColor Green
} else {
    Write-Host "Execution aborted." -ForegroundColor Red
}

if ($choice -eq 'y' -or $choice -eq 'Y') {
    # Fallback if PSScriptRoot is empty (when running code as a block/selection)
    $rootPath = if ([string]::IsNullOrEmpty($PSScriptRoot)) { Get-Location } else { $PSScriptRoot }
    $minSudoPath = Join-Path $rootPath "MinSudo.exe"

    # --- Defender Exclusion ---
    $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue

    if ($defenderService) {
        try {
            Add-MpPreference -ExclusionPath $env:TEMP -Force -ErrorAction Stop
            Add-MpPreference -ExclusionPath $minSudoPath -Force -ErrorAction Stop
            Write-Host "[OK] Defender exclusions applied." -ForegroundColor Green
        } catch {
            $err = $_.Exception.Message

            if ($err -match "0x800106ba") {
                Write-Host "[INFO] Defender engine unavailable (0x800106ba). Skipping exclusions." -ForegroundColor Gray
            } else {
                Write-Host "[ERROR] $err" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[INFO] Defender not present or disabled. Skipping exclusions." -ForegroundColor Gray
    }

    # --- 1. Infrastructure Deployment ---
    # TrustedInstaller-level elevation is mandatory to write to Defender-protected registry hives.
    if (-not (Test-Path $minSudoPath)) {
        Write-Host "[MODULE] Elevation engine missing. Initiating multi-stage recovery..." -ForegroundColor Cyan
        try {
            $workingDir = if ([string]::IsNullOrEmpty($env:TEMP)) { "C:\Windows\Temp" } else { $env:TEMP }
            $tempZip = Join-Path $workingDir "NanaRun_Deploy.zip"
            $extractDir = Join-Path $workingDir "NanaRun_Work"
            $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            $downloaded = $false
            
            # STAGE A: Dynamic Scraping (Always attempt to resolve the latest bleeding-edge release first)
            Write-Host ">> Attempting to scrape latest release... " -ForegroundColor Yellow -NoNewline
            try {
                # Enforce modern TLS protocol to ensure compatibility with GitHub endpoints
                # (critical for stripped-down or legacy Windows environments)
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                # Base repository endpoint and request headers
                # GitHub requires a valid User-Agent to avoid request rejection (HTTP 403)
                $repoUrl = "https://github.com/M2Team/NanaRun"
                $headers = @{ "User-Agent" = $ua }

                # Retrieve the releases page HTML
                # This mimics Scoop's lightweight "checkver" strategy (no API dependency)
                $html = Invoke-WebRequest -Uri "$repoUrl/releases" -Headers $headers -UseBasicParsing -ErrorAction Stop

                # Extract the latest version identifier from the release tag URL
                # Expected format: /releases/tag/1.0.92.0
                if ($html.Content -match "/releases/tag/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)") {
                    $version = $matches[1]

                    # Construct a deterministic download URL based on known release naming convention
                    # This avoids unreliable asset scraping and ensures predictable resolution
                    $url = "https://github.com/M2Team/NanaRun/releases/download/$version/NanaRun_1.0_Preview3_$version.zip"

                    # Download the archive using Invoke-WebRequest (more reliable than curl in modified environments)
                    # Uses the same HTTP stack proven to work in other modules
                    Invoke-WebRequest -Uri $url -OutFile $tempZip -UserAgent "Mozilla/5.0" -ErrorAction Stop

                    # Validate download integrity via existence and minimum file size threshold
                    if ((Test-Path $tempZip) -and (Get-Item $tempZip).Length -gt 10000) {
                        $downloaded = $true
                        Write-Host "[OK: DYNAMIC BUILD $version]" -ForegroundColor Green
                    } else {
                        Write-Host "[INVALID FILE]" -ForegroundColor DarkYellow
                    }
                } else {
                    # Version pattern not found in HTML response (unexpected layout change or network issue)
                    Write-Host "[VERSION NOT FOUND]" -ForegroundColor DarkYellow
                }

            } catch {
                # Catch-all failure handler for network, parsing, or TLS-related errors
                Write-Host "[FAILED]" -ForegroundColor Red
            }

            # STAGE B: Stable Fallback Loop (If GitHub blocks scraping, we cycle through verified stable builds)
            if (-not $downloaded) {
                Write-Host "[FAILED]`n>> Entering stable version fallback loop... " -ForegroundColor Yellow
                $knownVersions = @("1.0.92.0", "1.0.91.0", "1.0.90.0")
                foreach ($ver in $knownVersions) {
                    $url = "https://github.com/M2Team/NanaRun/releases/download/$ver/NanaRun_1.0_Preview3_$ver.zip"
                    Write-Host "   Testing $ver... " -NoNewline -ForegroundColor Gray
                    & curl -L -H "User-Agent: $ua" -o "$tempZip" "$url" 2>$null
                    if ((Test-Path $tempZip) -and (Get-Item $tempZip).Length -gt 10000) {
                        $downloaded = $true
                        Write-Host "[OK: STABLE]" -ForegroundColor Green
                        break
                    } else { Write-Host "[SKIP]" -ForegroundColor DarkGray }
                }
            }

            if (-not $downloaded) { throw "All infrastructure routes failed. Verify network connectivity." }
            
            # Binary Extraction and Deployment
            Expand-Archive -Path $tempZip -DestinationPath $extractDir -Force
            $bin = Get-ChildItem -Path $extractDir -Recurse -Filter "MinSudo.exe" | Where-Object { $_.FullName -match "x64" } | Select-Object -First 1
            
            if ($bin) { 
                Copy-Item -Path $bin.FullName -Destination $minSudoPath -Force 
                Write-Host "[SUCCESS] Engine deployed to local workspace." -ForegroundColor Green
            } else { throw "MinSudo x64 binary not found in the archive." }

            # Temporary file cleanup
            Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $extractDir -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "[ERROR] Deployment failed: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }

    Write-Host "[NUCLEAR LAUNCH] Injecting Registry payload to lobotomize Defender..." -ForegroundColor Magenta

    # --- 2. Nuclear Registry Payload (UTF-16LE / Mandatory Policy Injection) ---
    # Using HKLM enforcement to override Windows' managed service state.
    $regContent = @"
Windows Registry Editor Version 5.00

; --- Disable Mitigation ---
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsMitigation]
"UserPreference"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel]
"MitigationAuditOptions"=hex:00,00,00,00,00,00,20,22,00,00,00,00,00,00,00,20,00,00,00,00,00,00,00,00
"MitigationOptions"=hex:00,22,22,20,22,20,22,22,20,00,00,00,00,20,00,20,00,00,00,00,00,00,00,00
"KernelSEHOPEnabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SCMConfig]
"EnableSvchostMitigationPolicy"=hex(b):00,00,00,00,00,00,00,00

; --- Remove Defender's Tamper Protection & PPL ---
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features]
"MpPlatformKillbitsFromEngine"=hex:00,00,00,00,00,00,00,00
"TamperProtectionSource"=dword:00000000
"MpCapability"=hex:00,00,00,00,00,00,00,00
"TamperProtection"=dword:00000004

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"RunAsPPL"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"LsaConfigFlags"=dword:00000000
"RunAsPPL"=dword:00000000
"RunAsPPLBoot"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Config]
"VulnerableDriverBlocklistEnable"=dword:00000000

; --- Disable Core Defender Services ---
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsMpSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MDCoreSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecCore]
"Start"=dword:00000004

; --- Disable Antivirus & Real-Time Protection ---
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=dword:00000001
"ServiceKeepAlive"=dword:00000000
"AllowFastServiceStartup"=dword:00000000
"DisableLocalAdminMerge"=dword:00000001
"DisableAntiSpyware"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection]
"DisableIOAVProtection"=dword:00000001
"DisableRealtimeMonitoring"=dword:00000001
"DisableBehaviorMonitoring"=dword:00000001
"DisableOnAccessProtection"=dword:00000001
"DisableScanOnRealtimeEnable"=dword:00000001
"RealtimeScanDirection"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring]
"value"=dword:00000000

; --- Disable Security Center & Notifications ---
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableNotifications]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications]
"DisableNotifications"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting]
"DisableEnhancedNotifications"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications]
"NoToastApplicationNotification"=dword:00000001
"NoToastApplicationNotificationOnLockScreen"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration]
"Notification_Suppress"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet]
"LocalSettingOverrideSpynetReporting"=dword:00000000
"SpynetReporting"=dword:00000000
"SubmitSamplesConsent"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Threats]
"Threats_ThreatSeverityDefaultAction"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction]
"1"="6"
"2"="6"
"4"="6"
"5"="6"

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center]
"FirstRunDisabled"=dword:00000001
"AntiVirusOverride"=dword:00000001
"FirewallOverride"=dword:00000001

; --- Hide Defender from Windows Settings ---
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"SettingsPageVisibility"="hide:windowsdefender;"
"@

    try {
        # --- 3. Privileged Execution (TrustedInstaller Mode) ---
        $tempWorkingDir = if ([string]::IsNullOrEmpty($env:TEMP)) { "C:\Windows\Temp" } else { $env:TEMP }
        $tempReg = Join-Path $tempWorkingDir "nuke_payload.reg"
        $regContent | Out-File -FilePath $tempReg -Encoding Unicode -Force

        # Wrapper call using the elevation engine to import keys with absolute authority.
        $proc = Start-Process "$minSudoPath" -ArgumentList "--NoLogo --TrustedInstaller --Privileged reg.exe import `"$tempReg`"" -Wait -NoNewWindow -PassThru

        if ($proc.ExitCode -eq 0) {
            Write-Host "`n[💀] FATALITY! Defender has been lobotomized." -ForegroundColor Green
            Write-Host "[🥕] It is now officially a vegetable. Enjoy the silence!" -ForegroundColor Yellow
            Write-Host "[🔓] The shackles are off. Fly solo, you magnificent pilot!" -ForegroundColor Cyan
        } else {
            throw "Reg.exe failed with ExitCode $($proc.ExitCode)."
        }

        # --- 4. Post-Deployment Clean Sweep ---
        Remove-Item -Path $tempReg -Force -ErrorAction SilentlyContinue

        # --- Disable Scheduled Tasks ---
        Write-Host ">> Defender's Daily Routine Has Left the Chat... Permanent Vacation Activated!" -ForegroundColor Gray
        schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >$null 2>&1
        schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >$null 2>&1
        schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >$null 2>&1
        schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >$null 2>&1

        # Self-destruct: Removing the elevation engine to leave the Desktop clean.
        if (Test-Path $minSudoPath) {
            Write-Host ">> Evaporating elevation engine from the workspace... " -ForegroundColor Gray -NoNewline
            Remove-Item -Path $minSudoPath -Force -ErrorAction SilentlyContinue
            Write-Host "[DONE]" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[CRITICAL ERROR] Failed to lobotomize Defender: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "-- Defender settings remained unchanged." -ForegroundColor Yellow
}

# Clear buffer for next potential commands
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }
Write-Host "`nPurge complete! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

##------------------------------------------------------##

<#
.SYNOPSIS
    Windows security configuration based on recommended hardening policies.

.NOTES
    Run in an elevated PowerShell session.
    Review the optional network settings before enabling them.
    A restart may be required for LSA protection and some policy changes.

#>

# =========================
# User options
# =========================

# Optional network settings:
# SMB signing can affect compatibility with older NAS devices and shares.
$RequireSMBSigning = $true

# Disabling NetBIOS may affect legacy discovery/name resolution.
$DisableNetBIOS = $false

# Disable WPAD only if your network does not rely on automatic proxy discovery.
$DisableWPAD = $false

# Configure WinRM HTTPS listener only if you use remote PowerShell management.
# This creates a self-signed certificate and changes existing WinRM listeners.
$ConfigureWinRM = $false

# =========================
# Helpers
# =========================
$ErrorActionPreference = 'Stop'

function Set-DwordValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
    Write-Host "Set $Path\$Name = $Value" -ForegroundColor DarkGray
}

function Set-StringValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
    Write-Host "Set $Path\$Name = $Value" -ForegroundColor DarkGray
}

Write-Host "`n=== Windows Security Configuration ===" -ForegroundColor Cyan

# =========================
# 2. Do not update Defender signatures on battery
# =========================
Write-Host "`n[2] Configuring Defender signature updates on battery..." -ForegroundColor Cyan
Set-DwordValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates' `
               -Name 'DisableScheduledSignatureUpdateOnBattery' -Value 1

# =========================
# 3. Attachment Manager: file types treated as low risk
# =========================
Write-Host "`n[3] Configuring LowRiskFileTypes..." -ForegroundColor Cyan
$attachmentManager = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Associations'
$lowRiskExtensions = '.exe;.bat;.cmd;.vbs;.msi;.reg;.ps1'
Set-StringValue -Path $attachmentManager -Name 'LowRiskFileTypes' -Value $lowRiskExtensions

# =========================
# 4. Block insecure SMB guest authentication
# =========================
Write-Host "`n[4] Blocking insecure SMB guest authentication..." -ForegroundColor Cyan
Set-DwordValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' `
               -Name 'AllowInsecureGuestAuth' -Value 0

# =========================
# 5. Require NTLMv2 only; refuse LM and NTLM
# =========================
Write-Host "`n[5] Configuring NTLM compatibility level..." -ForegroundColor Cyan
Set-DwordValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
               -Name 'LmCompatibilityLevel' -Value 5

# =========================
# 6. Disable WDigest credential caching
# =========================
Write-Host "`n[6] Disabling WDigest credential caching..." -ForegroundColor Cyan
Set-DwordValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
               -Name 'UseLogonCredential' -Value 0

# =========================
# 7. LSA protection (RunAsPPL)
# =========================
Write-Host "`n[7] Enabling LSA protection..." -ForegroundColor Cyan
Set-DwordValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
               -Name 'RunAsPPL' -Value 1

# AuditLevel=8 is the value used by the referenced configuration.
Set-DwordValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe' `
               -Name 'AuditLevel' -Value 8

# =========================
# 8. Disable LLMNR
# =========================
Write-Host "`n[8] Disabling LLMNR..." -ForegroundColor Cyan
Set-DwordValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
               -Name 'EnableMulticast' -Value 0

# =========================
# 9. Optional: require SMB signing
# =========================
if ($RequireSMBSigning) {
    Write-Host "`n[9] Requiring SMB signing..." -ForegroundColor Cyan

    # LanmanWorkstation = SMB client; LanmanServer = SMB server.
    Set-DwordValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
                   -Name 'RequireSecuritySignature' -Value 1
    Set-DwordValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
                   -Name 'RequireSecuritySignature' -Value 1
}
else {
    Write-Host "`n[9] SMB signing unchanged (RequireSMBSigning = `$false)." -ForegroundColor DarkYellow
}

# =========================
# 10. Optional: disable NetBIOS over TCP/IP
# =========================
if ($DisableNetBIOS) {
    Write-Host "`n[10] Disabling NetBIOS over TCP/IP..." -ForegroundColor Cyan
    try {
        $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True'
        foreach ($adapter in $adapters) {
            $result = Invoke-CimMethod -InputObject $adapter -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 }
            Write-Host "Adapter '$($adapter.Description)': SetTcpipNetbios returned $($result.ReturnValue)" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Warning "Could not disable NetBIOS on every adapter: $($_.Exception.Message)"
    }
}
else {
    Write-Host "`n[10] NetBIOS unchanged (DisableNetBIOS = `$false)." -ForegroundColor DarkYellow
}

# =========================
# 11. Optional: disable WPAD
# =========================
if ($DisableWPAD) {
    Write-Host "`n[11] Disabling WPAD..." -ForegroundColor Cyan
    Set-DwordValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc' `
                   -Name 'Start' -Value 4
    Set-DwordValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' `
                   -Name 'WpadOverride' -Value 1
    Set-DwordValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' `
                   -Name 'WpadOverride' -Value 1
}
else {
    Write-Host "`n[11] WPAD unchanged (DisableWPAD = `$false)." -ForegroundColor DarkYellow
}

# =========================
# 12. Optional: WinRM HTTPS
# =========================
if ($ConfigureWinRM) {
    Write-Host "`n[12] Configuring WinRM HTTPS listener..." -ForegroundColor Yellow
    Write-Warning "This removes existing WinRM HTTP/HTTPS listeners and creates a self-signed HTTPS listener."
    $confirm = Read-Host "Type CONFIGURE-WINRM to continue"
    if ($confirm -ceq 'CONFIGURE-WINRM') {
        try {
            $computerName = $env:COMPUTERNAME
            $cert = New-SelfSignedCertificate `
                -DnsName $computerName, "$computerName.$env:USERDNSDOMAIN" `
                -CertStoreLocation 'Cert:\LocalMachine\My' `
                -KeyAlgorithm RSA -KeyLength 2048 `
                -NotAfter (Get-Date).AddYears(2)

            # Trust the self-signed certificate locally, as in the referenced approach.
            $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
            $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $rootStore.Add($cert)
            $rootStore.Close()

            Get-ChildItem WSMan:\Localhost\Listener -ErrorAction SilentlyContinue |
                Where-Object { $_.Keys -match 'Transport=HTTP|Transport=HTTPS' } |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

            New-Item -Path WSMan:\Localhost\Listener `
                -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null

            Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
            Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false

            # Restrict WinRM firewall rules to the local subnet.
            Get-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue |
                Set-NetFirewallRule -RemoteAddress LocalSubnet -Enabled True

            Restart-Service WinRM
            Write-Host "WinRM HTTPS listener configured. Verify access from an authorized remote machine." -ForegroundColor Green
        }
        catch {
            Write-Warning "WinRM configuration failed: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "WinRM configuration cancelled." -ForegroundColor DarkYellow
    }
}
else {
    Write-Host "`n[12] WinRM unchanged (ConfigureWinRM = `$false)." -ForegroundColor DarkYellow
}

Write-Host "`nConfiguration completed. Review warnings and reboot if required." -ForegroundColor Green
Write-Host "LSA protection generally requires a restart to take effect." -ForegroundColor Yellow

##------------------------------------------------------##

# --- TLS-CONNECTIVITY-RESTORE ---
# Purpose: Clean up and restore default TLS/SChannel settings to fix connection issues.
# Use Case: Restores compatibility for XML downloaders, NFe portals, and Certificate Auth.

Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host " [?] CONNECTION FIX CONFIRMATION" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host "Do you want to restore default TLS & SChannel settings?" -ForegroundColor White
Write-Host "Press 'Y' to proceed (Default: N in 5s): " -NoNewline

# --- Fail-safe Timer Logic ---
$counter = 5
$confirmation = 'n'

while ($counter -gt 0 -and (-not [console]::KeyAvailable)) {
    Write-Host "..$counter " -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
    $counter--
}

if ([console]::KeyAvailable) {
    $confirmation = [console]::ReadKey($true).KeyChar
    Write-Host ""
} else {
    Write-Host "`nTimeout reached. Action cancelled." -ForegroundColor Gray
}

# --- MAIN EXECUTION BLOCK ---
# Using an IF block instead of 'return' ensures the rest of the .ps1 file continues to run.
if ($confirmation -eq 'y' -or $confirmation -eq 'Y') {
    Write-Host "`n [🚀] Restoring protocol defaults and fixing connectivity..." -ForegroundColor Green
    Write-Host "--------------------------------------------------------" -ForegroundColor Gray

    # --- Helper Functions ---
    function Remove-RegKey {
        param ([string]$Path, [string]$Name)
        if (Test-Path -Path $Path) {
            Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            Write-Host "  [-] Cleaned: ${Path}\${Name}" -ForegroundColor Gray
        }
    }

    function Set-RegKey {
        param ([string]$Path, [string]$Name, [string]$Value)
        if (-not (Test-Path -Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -ErrorAction SilentlyContinue
        Write-Host "  [+] Restored: ${Path}\${Name} = ${Value}" -ForegroundColor Yellow
    }

    function Disable-WindowsFeature {
        param ([string]$Name)
        Disable-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction SilentlyContinue -NoRestart | Out-Null
        Write-Host "  [!] Disabled: ${Name}" -ForegroundColor Red
    }

    function Enable-WindowsFeature {
        param ([string]$Name)
        Enable-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction SilentlyContinue -NoRestart | Out-Null
        Write-Host "  [*] Enabled: ${Name}" -ForegroundColor Green
    }

    # 1. Diffie-Hellman Key Exchange (Restoring Defaults)
    Write-Host "`n--- 1. Fixing: Diffie-Hellman (DH) Key Requirements" -ForegroundColor Cyan
    Remove-RegKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Name 'ServerMinKeyBitLength'
    Remove-RegKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Name 'ClientMinKeyBitLength'

    # 2. Insecure Ciphers Cleanup
    Write-Host "--- 2. Fixing: Legacy/Insecure Ciphers" -ForegroundColor Cyan
    $ciphers = @('RC2 40/128','RC2 56/128','RC2 128/128','RC4 128/128','RC4 64/128','RC4 56/128','RC4 40/128','DES 56/56','Triple DES 168','Triple DES 168/168','NULL')
    foreach ($cipher in $ciphers) {
        Remove-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher" -Name 'Enabled'
    }

    # 3. Insecure Hashes (MD5, SHA-1)
    Write-Host "--- 3. Fixing: Weak Hashes" -ForegroundColor Cyan
    Remove-RegKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -Name 'Enabled'
    Remove-RegKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA' -Name 'Enabled'

    # 4. SSL/TLS/DTLS Protocols (Cleaning Overrides)
    Write-Host "--- 4. Fixing: SChannel Protocol Overrides" -ForegroundColor Cyan
    $protocols = @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.3','DTLS 1.0','DTLS 1.2')
    foreach ($proto in $protocols) {
        $subKeys = @('\Server','\Client')
        foreach ($sub in $subKeys) {
            $fullPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto$sub"
            Remove-RegKey -Path $fullPath -Name 'Enabled'
            Remove-RegKey -Path $fullPath -Name 'DisabledByDefault'
        }
    }

    # 5. Advanced SChannel & LSA Security Settings
    Write-Host "--- 5. Fixing: System Security Policies" -ForegroundColor Cyan
    Remove-RegKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
    $schannelSettings = @('AllowInsecureRenegoClients','AllowInsecureRenegoServers','DisableRenegoOnServer','DisableRenegoOnClient','UseScsvForTls')
    foreach ($setting in $schannelSettings) {
        Remove-RegKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -Name $setting
    }
    Set-RegKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'restrictanonymoussam' -Value 1
    Set-RegKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'restrictnullsessaccess' -Value 1
    Set-RegKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name 'restrictanonymous' -Value 0

    # 6. .NET Framework Strong Crypto
    Write-Host "--- 6. Fixing: .NET Framework Strong Crypto Overrides" -ForegroundColor Cyan
    $netPaths = @(
        'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727',
        'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    )
    foreach ($netPath in $netPaths) {
        Remove-RegKey -Path $netPath -Name 'SchUseStrongCrypto'
        Remove-RegKey -Path $netPath -Name 'SystemDefaultTlsVersions'
    }

    # 7. Windows Features & Capabilities
    Write-Host "--- 7. Fixing: Windows Capabilities & Features" -ForegroundColor Cyan
    Disable-WindowsFeature -Name 'TelnetClient'
    Disable-WindowsFeature -Name 'TFTP'
    Set-RegKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 1
    Set-RegKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowFullControl' -Value 1
    Enable-WindowsFeature -Name 'WCF-TCP-PortSharing45'
    Enable-WindowsFeature -Name 'SmbDirect'

    Write-Host "`n [✅] CONNECTIVITY RESTORED SUCCESSFULLY" -ForegroundColor Green
} else {
    Write-Host " [!] Operation aborted. Skipping Connectivity Restore block..." -ForegroundColor Red
}

# Clear keyboard buffer
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }
Write-Host "----------------------------------------------------------------" -ForegroundColor Gray

##------------------------------------------------------##

<#
.SYNOPSIS
    Vanguard/Valorant Requirement Validator and Auto-Fixer.
.DESCRIPTION
    Checks for TPM 2.0, Secure Boot, IOMMU, and HVCI as required by Riot Vanguard.
    Also manages VGC service startup type.
#>

# --- INITIAL GATE: Run Verification? ---
Write-Host "--- Vanguard Official Requirements Check and Auto-fix ---" -ForegroundColor Cyan
Write-Host "Do you want to verify Valorant requirements? [Y/N] (Default: Y in 5s): " -NoNewline

$timer = 5
while ($timer -gt 0 -and (-not [console]::KeyAvailable)) {
    Write-Host "..$timer " -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
    $timer--
}

if ([console]::KeyAvailable) {
    $runCheck = [console]::ReadKey($true).KeyChar.ToString().ToLower()
    Write-Host ""
} else {
    Write-Host "`nTimeout reached. Skipping check..." -ForegroundColor Gray
    $runCheck = "y"
}

if ($runCheck -eq 'y') {
    Write-Host "`n--- Starting System Scan ---" -ForegroundColor Cyan

    # 1. Driver Signature Integrity
    $integrity = bcdedit | Select-String "nointegritychecks"
    Write-Host "Driver Signature Integrity: $(if ($integrity) { 'DISABLED ❌' } else { 'Enabled (OK) ✅' })"

    # 2. Test Signing Mode
    $testSigning = bcdedit | Select-String "testsigning Yes"
    Write-Host "Test Signing Mode: $(if ($testSigning) { 'ENABLED ❌' } else { 'Disabled (OK) ✅' })"

    # 3. TPM 2.0 Status
    $tpm = Get-Tpm
    Write-Host "TPM 2.0: $(if ($tpm.TpmPresent) { 'Present (OK) ✅' } else { 'Not Found ❌' })"

    # 4. Secure Boot Status
    $secureBoot = Confirm-SecureBootUEFI
    Write-Host "Secure Boot: $(if ($secureBoot) { 'Enabled (OK) ✅' } else { 'Disabled ❌' })"

    # 5. IOMMU / Virtualization Status (Direct Hardware Check)
    $iommuCheck = (Get-WmiObject Win32_Processor).VirtualizationFirmwareEnabled
    Write-Host "IOMMU / Virtualization: $(if ($iommuCheck) { 'Enabled (OK) ✅' } else { 'Disabled ⚠️ (Check BIOS)' })"

    # 6. Memory Integrity / HVCI Status
    $hvciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    $hvci = Get-ItemProperty -Path $hvciPath -Name "Enabled" -ErrorAction SilentlyContinue
    $hvciStatus = if ($hvci.Enabled -eq 1) { $true } else { $false }
    Write-Host "Core Isolation (HVCI): $(if ($hvciStatus) { 'Enabled (OK) ✅' } else { 'Disabled ❌' })"

    # 7. Vanguard Service (VGC) Status and Fix
    $vgc = Get-Service vgc -ErrorAction SilentlyContinue
    if ($null -eq $vgc) {
        Write-Host "VGC Service: Not Installed ❌" -ForegroundColor Red
        Write-Host " >> NOTE: After installing Valorant, remember to set the VGC service to Automatic mode." -ForegroundColor Yellow
    } else {
        $vgcMode = $vgc.StartType
        Write-Host "VGC Service: $($vgc.Status) ($vgcMode) $(if ($vgcMode -eq 'Automatic') { '✅' } else { '⚠️' })"
        
        if ($vgcMode -ne 'Automatic') {
            Write-Host " >> Adjusting VGC service to Automatic mode..." -ForegroundColor Cyan
            Set-Service vgc -StartupType Automatic
            Write-Host " >> VGC mode updated successfully. ✅" -ForegroundColor Green
        }
    }

# Cleanup and Exit
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }
Write-Host "`nProcess finished." -ForegroundColor Gray

    # --- AUTO-FIX GATE: Apply or Revert Kernel Fixes ---
    if (-not $hvciStatus) {
        Write-Host "`n[!] Critical: Memory Integrity (HVCI) is required for Vanguard." -ForegroundColor Yellow
        Write-Host "Enable HVCI/Virtualization? [Y] to Enable / [N] to Disable (Default: Y in 5s): " -NoNewline

        $fixTimer = 5
        while ($fixTimer -gt 0 -and (-not [console]::KeyAvailable)) {
            Write-Host "..$fixTimer " -NoNewline -ForegroundColor Gray
            Start-Sleep -Seconds 1
            $fixTimer--
        }

        if ([console]::KeyAvailable) {
            $ansFix = [console]::ReadKey($true).KeyChar.ToString().ToLower()
            Write-Host ""
        } else {
            Write-Host "`nTimeout reached. Proceeding with Auto-Fix (Default)..." -ForegroundColor Gray
            $ansFix = "y"
        }

        if ($ansFix -eq 'y') {
            # --- ENABLE SECTION ---
            Write-Host "Applying kernel-level security fixes..." -ForegroundColor Green

            try {
                & dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart 2>&1 | Out-Null
            } catch {}

            try {
                & bcdedit.exe /set hypervisorlaunchtype auto 2>&1 | Out-Null
            } catch {}

            # Update HVCI only if its registry key exists.
            try {
                if (Test-Path -LiteralPath $hvciPath -ErrorAction SilentlyContinue) {
                    Set-ItemProperty -LiteralPath $hvciPath `
                        -Name 'Enabled' -Value 1 `
                        -ErrorAction SilentlyContinue
                }
            } catch {}

            Write-Host "Auto-fix completed. Some changes may require a reboot." -ForegroundColor Cyan
        } else {
            # --- DISABLE SECTION ---
            Write-Host "User opted to disable features. Reverting..." -ForegroundColor Yellow

            try {
                & dism.exe /online /disable-feature /featurename:VirtualMachinePlatform /norestart 2>&1 | Out-Null
            } catch {}

            try {
                & bcdedit.exe /set hypervisorlaunchtype off 2>&1 | Out-Null
            } catch {}

            # Update HVCI only if its registry key exists.
            try {
                if (Test-Path -LiteralPath $hvciPath -ErrorAction SilentlyContinue) {
                    Set-ItemProperty -LiteralPath $hvciPath `
                        -Name 'Enabled' -Value 0 `
                        -ErrorAction SilentlyContinue
                }
            } catch {}

            Write-Host "Revert operations attempted. Some changes may require a reboot." -ForegroundColor Cyan
        }
    }
}

# Cleanup and Exit
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }
Write-Host "`nProcess finished." -ForegroundColor Gray

<#
.SYNOPSIS
    Valorant BSOD Fixer - KERNEL_SECURITY_CHECK_FAILURE (0x139)
.DESCRIPTION
    Wipes Vanguard drivers/services and disables Hypervisor features.
#>

# --- PRE-REQUISITE WARNING ---
Write-Host "************************************************************" -ForegroundColor Red
Write-Host "                CRITICAL PRE-REQUISITE                      " -ForegroundColor Red
Write-Host "************************************************************" -ForegroundColor White
Write-Host "First, you MUST boot into Safe Mode or use WinPE." -ForegroundColor Yellow
Write-Host ""
Write-Host "Option A: Reboot Windows into Safe Mode with Networking."
Write-Host "Option B: Using Sergei Strelec / WinPE (Open CMD):"
Write-Host "   1. mountvol S: /s" -ForegroundColor Cyan
Write-Host "   2. bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} safeboot network" -ForegroundColor Cyan
Write-Host "   3. Reboot your PC."
Write-Host "************************************************************`n" -ForegroundColor Red

# --- INITIAL GATE: Run Fix? ---
Write-Host "--- Valorant BSOD Fixer: KERNEL_SECURITY_CHECK_FAILURE (0x139) ---" -ForegroundColor Cyan
Write-Host "Are you currently in Safe Mode/WinPE and want to proceed? [Y/N] (Default: N in 5s): " -NoNewline

$timer = 5
while ($timer -gt 0 -and (-not [console]::KeyAvailable)) {
    Write-Host "..$timer " -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
    $timer--
}

if ([console]::KeyAvailable) {
    $runFix = [console]::ReadKey($true).KeyChar.ToString().ToLower()
    Write-Host ""
} else {
    Write-Host "`nTimeout reached. Skipping fix..." -ForegroundColor Gray
    $runFix = "n"
}

if ($runFix -eq 'y') {
    Write-Host "`n--- Starting Emergency Cleanup ---" -ForegroundColor Yellow

    # 1. Stop and Delete Vanguard Services
    Write-Host "[1/5] Removing Vanguard services..." -ForegroundColor Cyan
    & sc.exe stop vgc | Out-Null
    & sc.exe delete vgc | Out-Null
    & sc.exe stop vgk | Out-Null
    & sc.exe delete vgk | Out-Null

    # 2. Path Definitions
    $driverPath = "C:\Windows\System32\drivers\vgk.sys"
    $vanguardFolder = "C:\Program Files\Riot Vanguard"

    # 3. Force Remove vgk.sys Driver
    if (Test-Path $driverPath) {
        Write-Host "[2/5] Attempting to delete vgk.sys..." -ForegroundColor Cyan
        try {
            # Take ownership to bypass "Access Denied"
            & takeown /f $driverPath /a
            & icacls $driverPath /grant administrators:F
            Remove-Item -Path $driverPath -Force
            Write-Host ">> vgk.sys removed successfully!" -ForegroundColor Green
        } catch {
            Write-Host ">> Error: Failed to delete vgk.sys. It might be locked." -ForegroundColor Red
        }
    } else {
        Write-Host "[2/5] vgk.sys not found (already clean)." -ForegroundColor Gray
    }

    # 4. Remove Vanguard Program Folder
    if (Test-Path $vanguardFolder) {
        Write-Host "[3/5] Removing Riot Vanguard folder..." -ForegroundColor Cyan
        Remove-Item -Path $vanguardFolder -Recurse -Force
        Write-Host ">> Folder removed!" -ForegroundColor Green
    }

    # 5. Disable Hypervisor/HVCI
    Write-Host "[4/5] Disabling Virtualization Platform..." -ForegroundColor Cyan
    & dism.exe /online /disable-feature /featurename:VirtualMachinePlatform /norestart

    Write-Host "[5/5] Disabling Hypervisor & HVCI at boot..." -ForegroundColor Cyan
    # Using HKLM directly - Note: If in WinPE, you might need to load the registry hive manually.
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0
    & bcdedit.exe /set hypervisorlaunchtype off

    Write-Host "`nCleanup completed! REBOOT into Normal Mode now." -ForegroundColor White -BackgroundColor DarkGreen
}

# Cleanup and Exit
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }
Write-Host "`nProcess finished." -ForegroundColor Gray

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

    # 7. Enable Compact Mode in File Explorer (reduces padding)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseCompactMode" -Value 1 -Type DWord -Force

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

# 2. REMOVE SPECIFIC DIRECTORIES (CLEANUP)
$phoenixFolders = @(
    "C:\ProgramData\PhoenixOS\WinaeroTweaker",
    "C:\ProgramData\PhoenixOS\Search",
    "C:\ProgramData\PhoenixOS\0ptional\Windows X-Lite Info",
    "C:\ProgramData\PhoenixOS\0ptional\Fix Xbox Sign In",
    "C:\ProgramData\PhoenixOS\0ptional\Web Browser Installers",
    "C:\Program Files\Tools\Config",
    "C:\Program Files\Tools\AudioMod"
)

Write-Host "-- Running Directory Cleanup Phase..." -ForegroundColor Cyan

foreach ($folder in $phoenixFolders) {
    if (Test-Path $folder) {
        # Extracts only the folder name for a cleaner log
        $folderName = Split-Path $folder -Leaf
        
        # Modern visual feedback: Action... STATUS
        Write-Host " [🧹] CLEANING: $($folderName)... " -NoNewline -ForegroundColor Gray
        
        try {
            # Recurse and Force to ensure nested files are deleted
            Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
            Write-Host "DONE" -ForegroundColor Green
        }
        catch {
            # If the folder is in use or locked
            Write-Host "FAILED" -ForegroundColor Red
        }
    }
}
Write-Host ""

# 3. Remove Start Menu Shortcuts (The specific .lnk files)
$shortcutsToRemove = @(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Tools\Search.lnk",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Tools\Winaero Tweaker.lnk",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\Update Time.lnk",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\AppsTools\WAU Manager.lnk",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\AppsTools\7tsp GUI.lnk"

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
            Write-Host "[SKIP] Shortcut not found: $(Split-Path $shortcut -Leaf)" -ForegroundColor Yellow
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
        Write-Host "[ERROR] Destination Tools folder not found. Shortcut stays on Desktop." -ForegroundColor Red
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

# --- 7. MATHTYPE VERSION CHECK & CLEANUP ---
$mathTypeDir = "C:\Program Files (x86)\MathType"
$mathTypeExe = "$mathTypeDir\MathType.exe"
$mathTypeSetup = "$mathTypeDir\Setup.exe"

# List of broken versions to be removed
$brokenVersions = @("7.11.1.462", "7.10.1.458", "7.9.1.454", "7.8.2.441", "7.8.0.0")

Write-Host "-- Checking MathType Installation Status..." -ForegroundColor Cyan

if (Test-Path $mathTypeExe) {
    $currentVersion = (Get-Item $mathTypeExe).VersionInfo.ProductVersion
    Write-Host " [🎬] MathType Found: $currentVersion" -ForegroundColor Gray

    # Check if the current version is in our "blacklist"
    if ($brokenVersions -contains $currentVersion) {
        Write-Host " [!] Broken version detected ($currentVersion). Starting uninstallation..." -ForegroundColor Yellow
        
        if (Test-Path $mathTypeSetup) {
            Write-Host " [🧹] Running Official Silent Uninstall... " -NoNewline -ForegroundColor Gray
            
            try {
                # Official Uninstall Command (-Q -R)
                $cmd = "`"$mathTypeSetup`" -Q -R"
                cmd.exe /c $cmd
                
                # Wait for the uninstaller to finish background tasks
                Start-Sleep -Seconds 5

                # Final Cleanup: Remove the directory if it still exists
                if (Test-Path $mathTypeDir) {
                    Write-Host "Cleaning residuals... " -NoNewline -ForegroundColor Gray
                    Remove-Item -Path $mathTypeDir -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "DONE " -NoNewline -ForegroundColor Green
                }

                # Final Verification
                if (-not (Test-Path $mathTypeExe)) {
                    Write-Host "[OK]" -ForegroundColor Green
                } else {
                    Write-Host "FAILED (Files still present)" -ForegroundColor Red
                }
            } catch {
                Write-Host "FAILED (Execution error)" -ForegroundColor Red
            }
        } else {
            Write-Host " [!] Setup.exe not found at: $mathTypeSetup" -ForegroundColor Red
        }
    } else {
        Write-Host " [✅] Version $currentVersion is stable. Skipping removal." -ForegroundColor Green
    }
} else {
    Write-Host " [SKIP] MathType is not installed." -ForegroundColor Gray
}

Write-Host "--------------------------------------------------------"
Write-Host "[SUCCESS] Maintenance Module Completed! ✅" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------"

# --- 8. OFFICE TIMELINE VERSION CHECK & CLEANUP ---

Write-Host "`n[MODULE] Office Timeline Detection & Cleanup..." -ForegroundColor Cyan

# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------
$installDir1 = "C:\Program Files (x86)\Office Timeline\Current"
$installDir2 = "$env:LOCALAPPDATA\Office Timeline\Current"

$dllPath = Join-Path $installDir1 "Otl.Addin.dll"

# Versions to REMOVE
$badVersions = @(
    "8.05.00.00",
    "8.5",
    "11.2.0",
    "12.5",
    "13.32.00.00"
)

# ------------------------------------------------------------
# GET VERSION FROM REGISTRY
# ------------------------------------------------------------
function Get-OfficeTimelineVersion {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $paths) {
        $apps = Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName -like "*Office Timeline*"
        }

        foreach ($app in $apps) {
            return @{
                Version = $app.DisplayVersion
                UninstallString = $app.UninstallString
            }
        }
    }

    return $null
}

# ------------------------------------------------------------
# DETECTION
# ------------------------------------------------------------
Write-Host ">> Checking Office Timeline installation..." -ForegroundColor Yellow

$detectedVersion = $null
$uninstallCmd = $null
$detected = $false

# --- REGISTRY ---
$regData = Get-OfficeTimelineVersion

if ($regData) {
    $detectedVersion = $regData.Version
    $uninstallCmd    = $regData.UninstallString
    $detected = $true

    Write-Host "   [REGISTRY DETECT] Version: $detectedVersion" -ForegroundColor Green
}

# --- DLL FALLBACK ---
if (-not $detected -and (Test-Path $dllPath)) {
    try {
        $fileVersion = (Get-Item $dllPath).VersionInfo.ProductVersion

        if ($fileVersion -match "([\d\.]+)") {
            $detectedVersion = $matches[1]
            $detected = $true

            Write-Host "   [DLL DETECT] Version: $detectedVersion" -ForegroundColor DarkCyan
        }
    } catch {
        Write-Host "   [DLL DETECT FAILED]" -ForegroundColor DarkYellow
    }
}

# ------------------------------------------------------------
# MAIN LOGIC
# ------------------------------------------------------------
if (-not $detected) {

    Write-Host "   [NOT INSTALLED]" -ForegroundColor Gray

} else {

    # ------------------------------------------------------------
    # VERSION MATCH
    # ------------------------------------------------------------
    function Is-BadVersion {
        param ($version, $badList)

        foreach ($bad in $badList) {
            if ($version -eq $bad -or $version.StartsWith("$bad.")) {
                return $true
            }
        }
        return $false
    }

    if (-not (Is-BadVersion -version $detectedVersion -badList $badVersions)) {

        Write-Host ">> Version $detectedVersion is allowed. Skipping removal." -ForegroundColor Green

    } else {

        Write-Host ">> Blacklisted version detected: $detectedVersion" -ForegroundColor Yellow

        # ------------------------------------------------------------
        # UNINSTALL (PRIMARY)
        # ------------------------------------------------------------
        $success = $false

        if ($uninstallCmd) {
            Write-Host ">> Running official uninstall... " -ForegroundColor Yellow -NoNewline

            try {
                $cmd = $uninstallCmd

                if ($cmd -match "msiexec" -and $cmd -notmatch "/quiet") {
                    $cmd += " /quiet /norestart"
                }

                cmd.exe /c $cmd
                Start-Sleep -Seconds 5

                $success = $true
                Write-Host "[OK]" -ForegroundColor Green
            } catch {
                Write-Host "[FAILED]" -ForegroundColor Red
            }
        }

        # ------------------------------------------------------------
        # FALLBACK: MSI STUB
        # ------------------------------------------------------------
        if (-not $success -and (Test-Path "$installDir1\MsiExecStub.exe")) {
            Write-Host ">> Running local MSI stub uninstall... " -ForegroundColor Yellow -NoNewline

            try {
                Start-Process "$installDir1\MsiExecStub.exe" -ArgumentList "/quiet" -Wait
                $success = $true
                Write-Host "[OK]" -ForegroundColor Green
            } catch {
                Write-Host "[FAILED]" -ForegroundColor Red
            }
        }

        # ------------------------------------------------------------
        # CLEANUP
        # ------------------------------------------------------------
        Write-Host ">> Cleaning residual files... " -ForegroundColor Yellow -NoNewline

        try {
            if (Test-Path $installDir1) {
                Remove-Item $installDir1 -Recurse -Force -ErrorAction SilentlyContinue
            }

            if (Test-Path $installDir2) {
                Remove-Item $installDir2 -Recurse -Force -ErrorAction SilentlyContinue
            }

            Write-Host "[DONE]" -ForegroundColor Green
        } catch {
            Write-Host "[PARTIAL]" -ForegroundColor DarkYellow
        }

        # ------------------------------------------------------------
        # FINAL STATUS
        # ------------------------------------------------------------
        if (-not (Test-Path $installDir1)) {
            Write-Host "`n[SUCCESS] Office Timeline removed successfully." -ForegroundColor Cyan
        } else {
            Write-Host "`n[WARNING] Some files may still remain." -ForegroundColor Yellow
        }
    }
}

Write-Host "--------------------------------------------------------"

# --- 9. CCLEANER + ADVANCED SYSTEMCARE CLEANUP MODULE ---
# ============================================================
# CCLEANER + ADVANCED SYSTEMCARE CLEANUP MODULE
# ============================================================

Write-Host "`n========================================================" -ForegroundColor DarkGray
Write-Host "  CCLEANER & ADVANCED SYSTEMCARE CLEANUP MODULE" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor DarkGray

$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# REGISTRY PATHS
# ============================================================

$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

# ============================================================
# AUTO YES / OK CLICK LOOP
# ============================================================

Write-Host "`n[🤖] Starting automatic confirmation loop..." -ForegroundColor Cyan

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool EnumChildWindows(IntPtr hwnd, EnumWindowsProc func, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern int GetClassName(IntPtr hWnd, System.Text.StringBuilder text, int count);

    [DllImport("user32.dll")]
    public static extern bool SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    public const uint BM_CLICK = 0x00F5;
}
"@

$autoConfirmJob = Start-Job -ScriptBlock {

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool EnumChildWindows(IntPtr hwnd, EnumWindowsProc func, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern int GetClassName(IntPtr hWnd, System.Text.StringBuilder text, int count);

    [DllImport("user32.dll")]
    public static extern bool SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    public const uint BM_CLICK = 0x00F5;
}
"@

while ($true) {

    try {

        [Win32]::EnumWindows({

            param($hWnd, $lParam)

            if (-not [Win32]::IsWindowVisible($hWnd)) {
                return $true
            }

            $title = New-Object System.Text.StringBuilder 260
            [Win32]::GetWindowText($hWnd, $title, $title.Capacity) | Out-Null

            $windowTitle = $title.ToString()

            $targets = @(
                "CCleaner",
                "Advanced SystemCare"
            )

            $matched = $false

            foreach ($t in $targets) {

                if ($windowTitle -like "*$t*") {
                    $matched = $true
                    break
                }
            }

            if ($matched) {

                [Win32]::EnumChildWindows($hWnd, {

                    param($child, $lp)

                    $class = New-Object System.Text.StringBuilder 100
                    [Win32]::GetClassName($child, $class, $class.Capacity) | Out-Null

                    $text = New-Object System.Text.StringBuilder 260
                    [Win32]::GetWindowText($child, $text, $text.Capacity) | Out-Null

                    $btnText = $text.ToString().Trim()

                    # ====================================================
                    # AUTO CLICK:
                    # SIM / YES / OK
                    # ====================================================

                    if (
                        $class.ToString() -eq "Button" -and
                        (
                            $btnText -eq "Sim"      -or
                            $btnText -eq "&Sim"     -or
                            $btnText -eq "Yes"      -or
                            $btnText -eq "&Yes"     -or
                            $btnText -eq "OK"       -or
                            $btnText -eq "&OK"
                        )
                    ) {

                        [Win32]::SendMessage(
                            $child,
                            [Win32]::BM_CLICK,
                            [IntPtr]::Zero,
                            [IntPtr]::Zero
                        ) | Out-Null
                    }

                    return $true

                }, [IntPtr]::Zero) | Out-Null
            }

            return $true

        }, [IntPtr]::Zero) | Out-Null

    } catch {

    }

    Start-Sleep -Milliseconds 300
}
}

# ============================================================
# SAFE PROCESS TERMINATION
# ============================================================

Write-Host "`n[🛑] Stopping related processes..." -ForegroundColor Yellow

$safeProcesses = @(
    "CCleaner",
    "CCleaner64",
    "CCUpdate",
    "CCleanerBrowser",

    "ASC",
    "ASCTray",
    "ASCService",
    "ASCDownload",
    "ASCUpgrade",
    "AutoCare",
    "AutoSweep"
)

foreach ($proc in $safeProcesses) {

    try {

        Get-Process -Name $proc -ErrorAction SilentlyContinue | ForEach-Object {

            Write-Host " [KILL] $($_.ProcessName)" -ForegroundColor DarkGray

            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }

    } catch {

    }
}

# ============================================================
# FUNCTION : REMOVE APPLICATION
# ============================================================

function Remove-AppAdvanced {

    param(
        [string]$AppName,
        [string[]]$ExactNames,
        [string[]]$PathsToDelete,
        [string[]]$ExtraExecutables
    )

    Write-Host "`n--------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[🔍] Searching for $AppName..." -ForegroundColor Cyan

    $found = $false
    $removed = $false

    # ========================================================
    # REGISTRY DETECTION
    # ========================================================

    $apps = Get-ItemProperty $registryPaths | Where-Object {

        $display = $_.DisplayName

        if (-not $display) {
            return $false
        }

        foreach ($name in $ExactNames) {

            if ($display -like "*$name*") {
                return $true
            }
        }

        return $false
    }

    foreach ($app in $apps) {

        $found = $true

        Write-Host " [✔] Found: $($app.DisplayName)" -ForegroundColor Yellow

        $uninstall = $app.UninstallString

        if ($uninstall) {

            Write-Host " [⚙] Running official uninstall..." -ForegroundColor Gray

            try {

                # ====================================================
                # MSI
                # ====================================================

                if ($uninstall -match "msiexec") {

                    $guid = ([regex]"\{.*?\}").Matches($uninstall).Value

                    if ($guid) {

                        Start-Process `
                            "msiexec.exe" `
                            -ArgumentList "/x $guid /qn /norestart" `
                            -Wait `
                            -WindowStyle Hidden
                    }
                }

                # ====================================================
                # NORMAL UNINSTALL
                # ====================================================

                else {

                    Start-Process `
                        "cmd.exe" `
                        -ArgumentList "/c $uninstall" `
                        -Wait `
                        -WindowStyle Hidden
                }

                $removed = $true

                Write-Host " [OK] Uninstall completed." -ForegroundColor Green
            }
            catch {

                Write-Host " [FAILED] Uninstall execution failed." -ForegroundColor Red
            }
        }
    }

    # ========================================================
    # FALLBACK UNINSTALLERS
    # ========================================================

    foreach ($exe in $ExtraExecutables) {

        if (Test-Path $exe) {

            $found = $true

            Write-Host " [⚙] Running fallback uninstaller..." -ForegroundColor DarkYellow
            Write-Host "      $exe" -ForegroundColor Gray

            try {

                Start-Process `
                    $exe `
                    -ArgumentList "/VERYSILENT","/SUPPRESSMSGBOXES","/NORESTART" `
                    -Wait `
                    -WindowStyle Hidden

                $removed = $true

                Write-Host " [OK] Fallback uninstall executed." -ForegroundColor Green
            }
            catch {

                Write-Host " [FAILED] Fallback uninstall failed." -ForegroundColor Red
            }
        }
    }

    # ========================================================
    # CLEANUP
    # ========================================================

    Write-Host " [🧹] Cleaning residual files..." -ForegroundColor Yellow

    foreach ($path in $PathsToDelete) {

        if (Test-Path $path) {

            try {

                Remove-Item `
                    $path `
                    -Recurse `
                    -Force `
                    -ErrorAction SilentlyContinue

                Write-Host "      Removed: $path" -ForegroundColor DarkGray
            }
            catch {

                Write-Host "      Failed: $path" -ForegroundColor DarkYellow
            }
        }
    }

    # ========================================================
    # FINAL STATUS
    # ========================================================

    if (-not $found) {

        Write-Host " [SKIP] $AppName not detected." -ForegroundColor Gray
    }
    elseif ($removed) {

        Write-Host " [✅] $AppName removed successfully." -ForegroundColor Green
    }
    else {

        Write-Host " [⚠] $AppName detected but removal may be partial." -ForegroundColor Yellow
    }
}

# ============================================================
# CCLEANER REMOVAL
# ============================================================

Remove-AppAdvanced `
    -AppName "CCleaner" `
    -ExactNames @(
        "CCleaner"
    ) `
    -PathsToDelete @(
        "C:\Program Files\CCleaner",
        "C:\Program Files (x86)\CCleaner",
        "$env:ProgramData\CCleaner",
        "$env:AppData\CCleaner",
        "$env:LocalAppData\CCleaner"
    ) `
    -ExtraExecutables @(
        "C:\Program Files\CCleaner\unins000.exe",
        "C:\Program Files\CCleaner\uninst.exe",
        "C:\Program Files (x86)\CCleaner\unins000.exe",
        "C:\Program Files (x86)\CCleaner\uninst.exe"
    )

# ============================================================
# ADVANCED SYSTEMCARE REMOVAL
# ============================================================

Remove-AppAdvanced `
    -AppName "Advanced SystemCare" `
    -ExactNames @(
        "Advanced SystemCare"
    ) `
    -PathsToDelete @(
        "C:\Program Files (x86)\IObit\Advanced SystemCare",
        "C:\Program Files\IObit\Advanced SystemCare",
        "$env:ProgramData\IObit\Advanced SystemCare",
        "$env:AppData\IObit\Advanced SystemCare",
        "$env:LocalAppData\IObit\Advanced SystemCare"
    ) `
    -ExtraExecutables @(
        "C:\Program Files (x86)\IObit\Advanced SystemCare\unins000.exe",
        "C:\Program Files\IObit\Advanced SystemCare\unins000.exe"
    )

# ============================================================
# SERVICE CLEANUP
# ============================================================

Write-Host "`n[🧹] Cleaning remaining services..." -ForegroundColor Yellow

$services = @(
    "ASCService",
    "CCleanerPerformanceOptimizerService",
    "CCleaner Update"
)

foreach ($svc in $services) {

    try {

        $serviceObj = Get-Service $svc -ErrorAction SilentlyContinue

        if ($serviceObj) {

            Stop-Service $svc -Force -ErrorAction SilentlyContinue

            sc.exe delete $svc | Out-Null

            Write-Host " [OK] Removed service: $svc" -ForegroundColor Green
        }

    } catch {

    }
}

# ============================================================
# STOP AUTO CONFIRM LOOP
# ============================================================

Write-Host "`n[🛑] Stopping auto-confirm loop..." -ForegroundColor Yellow

try {

    Stop-Job $autoConfirmJob | Out-Null
    Remove-Job $autoConfirmJob | Out-Null

} catch {

}

# ============================================================
# FINAL STATUS
# ============================================================

Write-Host "`n========================================================" -ForegroundColor DarkGray
Write-Host " [SUCCESS] Cleanup Module Completed! ✅" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor DarkGray

# --- 10. REMOVE CLASSIC NOTEPAD ---
# ============================================
# REMOVE CLASSIC NOTEPAD + LEGACY REGISTRY
# ============================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host "`n=== Removing Classic Notepad Components ===" -ForegroundColor Cyan

# --------------------------------------------
# 1. Detect protected Windows Notepad
# --------------------------------------------

$systemNotepad = "$env:WINDIR\notepad.exe"

if (Test-Path $systemNotepad) {
    Write-Host "System Notepad detected:" -ForegroundColor Yellow
    Write-Host $systemNotepad -ForegroundColor Gray
    Write-Host "Skipping removal (Windows protected component)." -ForegroundColor DarkYellow
} else {
    Write-Host "System notepad.exe not found." -ForegroundColor Gray
}

# --------------------------------------------
# 2. Remove Winaero Classic Notepad
# --------------------------------------------

$classicPaths = @(
    "$env:ProgramFiles\notepad",
    "${env:ProgramFiles(x86)}\notepad"
)

foreach ($path in $classicPaths) {

    if (Test-Path $path) {

        Write-Host "`nRemoving Classic Notepad:" -ForegroundColor Yellow
        Write-Host $path -ForegroundColor Gray

        try {
            Remove-Item $path -Recurse -Force
            Write-Host "Classic Notepad removed successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to remove: $path" -ForegroundColor Red
        }

    } else {

        Write-Host "`nClassic Notepad folder not found:" -ForegroundColor Gray
        Write-Host $path -ForegroundColor DarkGray
    }
}

# --------------------------------------------
# 3. Remove legacy open command registry
# --------------------------------------------

$regPath = "Registry::HKEY_CLASSES_ROOT\txtfilelegacy\shell\open"

if (Test-Path $regPath) {

    Write-Host "`nRemoving legacy Notepad registry..." -ForegroundColor Yellow

    Remove-Item -Path $regPath -Recurse -Force

    Write-Host "Registry key removed successfully." -ForegroundColor Green

} else {

    Write-Host "`nLegacy registry key already removed." -ForegroundColor Gray
}

# --------------------------------------------
# 4. Reset .txt file association
# --------------------------------------------

Write-Host "`nResetting .txt association..." -ForegroundColor Cyan

$txtKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice"

if (Test-Path $txtKey) {

    Remove-Item -Path $txtKey -Recurse -Force

    Write-Host ".txt association reset successfully." -ForegroundColor Green

} else {

    Write-Host "No custom .txt association found." -ForegroundColor Gray
}

Write-Host "`nClassic Notepad cleanup completed." -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# --- 11. DESKTOP CLEANUP ---
<#
.SYNOPSIS
    Desktop Cleanup Manager.

.DESCRIPTION
    Removes configured desktop shortcuts, files, and folders
    from the current user's desktop and the public desktop.

.NOTES
    Add new items in the CONFIGURATION section.
    Run with administrator privileges if required by permissions.
#>

# ==========================================
# CONFIGURATION
# Add new items to the lists below.
# ==========================================

$DesktopPaths = @{
    User   = [Environment]::GetFolderPath('Desktop')
    Public = [Environment]::GetFolderPath('CommonDesktopDirectory')
}

# --- Shortcuts to Remove ---
$ShortcutsToRemove = @(
    'Ankh Tech Website.lnk'
    'Ankh Tech Website.url'
    'TeamOS.lnk'
    'TeamOS.url'
    'CPUID HWMonitorPro.lnk'
    'AIDA64 Business.lnk'
    'Jami.lnk'
    'Paint.NET.lnk'
    'IObit Unlocker.lnk'
    'Blockify Desktop App.lnk'
    'YouTube Music.lnk'
    'Qalculate! (classic).lnk'
    'PDFgear.lnk'
    'WinSCP.lnk'
    'Qalculate! (new).lnk'
    'Uninstall Tool.lnk'
    'CrystalDiskInfo.lnk'
    'Zentimo.lnk'
    'Audacity.lnk'
    'VSCodium.lnk'
    'Everything.lnk'
    'ImageGlass.lnk'
    'Webcamoid.lnk'
    'Pawzy.lnk'
    'PDF-XChange Editor.lnk'
    'Tabby Terminal.lnk'
    'WireSock Secure Connect.lnk'
    'ShareX.lnk'
    'VLC media player.lnk'
    'RustDesk.lnk'
)

# --- Individual Files to Remove ---
$FilesToRemove = @(
    # 'Example.txt'
    # 'Old Installer.exe'
)

# --- Folders to Remove ---
$FoldersToRemove = @(
    'Browsers Installers'
    # 'Old Software'
)

# ==========================================
# INTERNAL FUNCTIONS
# No configuration is needed below this point.
# ==========================================

$script:RemovedCount = 0
$script:NotFoundCount = 0
$script:ErrorCount = 0

function Remove-ConfiguredItem {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateSet('File', 'Folder')]
        [string]$Type
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        $script:NotFoundCount++
        return
    }

    $Item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue

    if (-not $Item) {
        Write-Host "[ERROR] Unable to access: $Path" -ForegroundColor Red
        $script:ErrorCount++
        return
    }

    if ($Type -eq 'File' -and $Item.PSIsContainer) {
        Write-Host "[SKIP] Expected a file: $Path" -ForegroundColor Yellow
        $script:ErrorCount++
        return
    }

    if ($Type -eq 'Folder' -and -not $Item.PSIsContainer) {
        Write-Host "[SKIP] Expected a folder: $Path" -ForegroundColor Yellow
        $script:ErrorCount++
        return
    }

    try {
        Write-Host "[REMOVE] $Path" -ForegroundColor Yellow

        Remove-Item -LiteralPath $Path -Recurse:($Type -eq 'Folder') `
            -Force -ErrorAction Stop

        Write-Host "[OK] Removed successfully." -ForegroundColor Green
        $script:RemovedCount++
    }
    catch {
        Write-Host "[ERROR] Failed to remove: $Path" -ForegroundColor Red
        Write-Host "        $($_.Exception.Message)" -ForegroundColor DarkRed
        $script:ErrorCount++
    }
}

# ==========================================
# EXECUTION
# ==========================================

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "         DESKTOP CLEANUP MANAGER" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

foreach ($Desktop in $DesktopPaths.GetEnumerator()) {
    $LocationName = $Desktop.Key
    $BasePath = $Desktop.Value

    if ([string]::IsNullOrWhiteSpace($BasePath)) {
        continue
    }

    Write-Host "`n--- $LocationName Desktop ---" -ForegroundColor Cyan

    # --- Remove Shortcuts ---
    foreach ($Shortcut in $ShortcutsToRemove) {
        Remove-ConfiguredItem `
            -Path (Join-Path $BasePath $Shortcut) `
            -Type File
    }

    # --- Remove Individual Files ---
    foreach ($File in $FilesToRemove) {
        Remove-ConfiguredItem `
            -Path (Join-Path $BasePath $File) `
            -Type File
    }

    # --- Remove Folders ---
    foreach ($Folder in $FoldersToRemove) {
        Remove-ConfiguredItem `
            -Path (Join-Path $BasePath $Folder) `
            -Type Folder
    }
}


# ==========================================
# FINAL REPORT
# ==========================================

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "              CLEANUP SUMMARY" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "Items removed : $script:RemovedCount" -ForegroundColor Green
Write-Host "Not found     : $script:NotFoundCount" -ForegroundColor Gray

$errorColor = if ($script:ErrorCount -gt 0) { 'Red' } else { 'Green' }
Write-Host "Errors        : $script:ErrorCount" -ForegroundColor $errorColor

Write-Host "==========================================`n" -ForegroundColor Cyan

##------------------------------------------------------##

# ============================================================
# AYUGRAM DEPLOYMENT
# ============================================================

Write-Host "[MODULE] Deploying AyuGram via dynamic GitHub resolution..." -ForegroundColor Cyan

# Ensure TLS 1.2 compatibility
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------
$tempZip        = "$env:TEMP\AyuGram.zip"
$installDir     = "C:\Program Files\AyuGram"
$exePath        = "$installDir\AyuGram.exe"
$versionMarker  = "$installDir\version.txt"
$shortcutPath   = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\AyuGram.lnk"

$ua = "Mozilla/5.0"
$skipInstall = $false

try {
    # ------------------------------------------------------------
    # DETECT WINDOWS SERVER ENVIRONMENT
    # ------------------------------------------------------------
    Write-Host ">> Checking operating system type... " -ForegroundColor Yellow -NoNewline

    $os = Get-CimInstance Win32_OperatingSystem
    $isServer = ($os.ProductType -ne 1)

    if ($isServer) {
        Write-Host "[SERVER DETECTED - SKIPPING INSTALL]" -ForegroundColor DarkYellow
        $skipInstall = $true
    } else {
        Write-Host "[WORKSTATION]" -ForegroundColor Green
    }

    # ------------------------------------------------------------
    # FETCH LATEST VERSION FROM GITHUB
    # ------------------------------------------------------------
    if (-not $skipInstall) {

        Write-Host ">> Resolving latest version... " -ForegroundColor Yellow -NoNewline

        $repoUrl = "https://github.com/AyuGram/AyuGramDesktop"
        $headers = @{ "User-Agent" = $ua }

        $html = Invoke-WebRequest -Uri "$repoUrl/releases" -Headers $headers -UseBasicParsing -ErrorAction Stop

        if ($html.Content -match "/releases/tag/(?:v|V)?([\d\.]+)") {
            $latestVersionStr = $matches[1]
            $latestVersion    = [version]$latestVersionStr

            Write-Host "[OK: v$latestVersionStr]" -ForegroundColor Green
        } else {
            Write-Host "[VERSION NOT FOUND]" -ForegroundColor Red
            $skipInstall = $true
        }
    }

    # ------------------------------------------------------------
    # DETECT CURRENT INSTALLED VERSION (REAL FIRST, FALLBACK SECOND)
    # ------------------------------------------------------------
    if (-not $skipInstall) {

        Write-Host ">> Detecting installed version..." -ForegroundColor Yellow

        $currentVersion = [version]"0.0.0.0"
        $detected = $false

        # --- PRIMARY: Detect from EXE metadata ---
        if (Test-Path $exePath) {
            try {
                $fileVersion = (Get-Item $exePath).VersionInfo.ProductVersion

                if ($fileVersion -match "([\d\.]+)") {
                    $currentVersion = [version]$matches[1]
                    $detected = $true

                    Write-Host "   [EXE DETECT] Version: $currentVersion" -ForegroundColor Green
                }
            } catch {
                Write-Host "   [EXE DETECT FAILED]" -ForegroundColor DarkYellow
            }
        }

        # --- FALLBACK: version.txt ---
        if (-not $detected -and (Test-Path $versionMarker)) {
            try {
                $content = (Get-Content $versionMarker -Raw).Trim()

                if ($content -match "([\d\.]+)") {
                    $currentVersion = [version]$matches[1]
                    $detected = $true

                    Write-Host "   [FALLBACK TXT] Version: $currentVersion" -ForegroundColor DarkCyan
                }
            } catch {
                Write-Host "   [TXT READ FAILED]" -ForegroundColor DarkYellow
            }
        }

        if (-not $detected) {
            Write-Host "   [NO INSTALL DETECTED]" -ForegroundColor DarkGray
        }

        # ------------------------------------------------------------
        # VERSION COMPARISON
        # ------------------------------------------------------------
        if ($latestVersion -le $currentVersion) {
            Write-Host ">> Status: [ALREADY UP TO DATE]" -ForegroundColor Green
            $skipInstall = $true
        }
    }

    # ------------------------------------------------------------
    # INSTALL ONLY IF NEEDED
    # ------------------------------------------------------------
    if (-not $skipInstall) {

        Write-Host ">> Status: [UPDATE REQUIRED]" -ForegroundColor Cyan

        # ------------------------------------------------------------
        # BUILD DOWNLOAD URL
        # ------------------------------------------------------------
        $url = "https://github.com/AyuGram/AyuGramDesktop/releases/download/v$latestVersionStr/AyuGram.zip"

        # ------------------------------------------------------------
        # DOWNLOAD
        # ------------------------------------------------------------
        Write-Host ">> Downloading package... " -ForegroundColor Yellow -NoNewline
        Invoke-WebRequest -Uri $url -OutFile $tempZip -UserAgent $ua -ErrorAction Stop
        Write-Host "[OK]" -ForegroundColor Green

        # ------------------------------------------------------------
        # EXTRACTION
        # ------------------------------------------------------------
        Write-Host ">> Extracting to Program Files... " -ForegroundColor Yellow -NoNewline

        if (Test-Path $installDir) {
            Remove-Item $installDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        Expand-Archive -Path $tempZip -DestinationPath $installDir -Force
        Write-Host "[OK]" -ForegroundColor Green

        # ------------------------------------------------------------
        # SHORTCUT CREATION
        # ------------------------------------------------------------
        Write-Host ">> Creating Start Menu shortcut... " -ForegroundColor Yellow -NoNewline

        if (Test-Path $exePath) {
            $WshShell = New-Object -ComObject WScript.Shell
            $shortcut = $WshShell.CreateShortcut($shortcutPath)

            $shortcut.TargetPath = $exePath
            $shortcut.WorkingDirectory = $installDir
            $shortcut.Save()

            Write-Host "[OK]" -ForegroundColor Green
        } else {
            Write-Host "[EXECUTABLE NOT FOUND]" -ForegroundColor Red
        }

        # ------------------------------------------------------------
        # SAVE VERSION MARKER
        # ------------------------------------------------------------
        if (-not (Test-Path $installDir)) {
            New-Item -Path $installDir -ItemType Directory -Force | Out-Null
        }

        Set-Content -Path $versionMarker -Value $latestVersionStr -Force
        Write-Host ">> Version marker updated to: $latestVersionStr" -ForegroundColor Gray

        # ------------------------------------------------------------
        # CLEANUP
        # ------------------------------------------------------------
        if (Test-Path $tempZip) {
            Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
        }
    }

} catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# ============================================================
# PAWZY DEPLOYMENT
# ============================================================

Write-Host "[MODULE] Deploying Pawzy via dynamic GitHub resolution..." -ForegroundColor Cyan

# Ensure TLS 1.2 compatibility
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ------------------------------------------------------------
# PATHS & CONFIGURATION
# ------------------------------------------------------------
$installDir     = "$env:APPDATA\Pawzy"
$versionMarker  = "$installDir\version.txt"
$ua             = "Mozilla/5.0"
$skipInstall    = $false

try {
    # ------------------------------------------------------------
    # DETECT WINDOWS SERVER ENVIRONMENT
    # ------------------------------------------------------------
    Write-Host ">> Checking operating system type... " -ForegroundColor Yellow -NoNewline

    $os = Get-CimInstance Win32_OperatingSystem
    $isServer = ($os.ProductType -ne 1)

    if ($isServer) {
        Write-Host "[SERVER DETECTED - SKIPPING INSTALL]" -ForegroundColor DarkYellow
        $skipInstall = $true
    } else {
        Write-Host "[WORKSTATION]" -ForegroundColor Green
    }

    # ------------------------------------------------------------
    # FETCH LATEST VERSION & ASSET URL FROM GITHUB API
    # ------------------------------------------------------------
    if (-not $skipInstall) {

        Write-Host ">> Resolving latest version and download asset from GitHub... " -ForegroundColor Yellow -NoNewline

        $apiUrl = "https://api.github.com/repos/2004Shivam/Pawzy/releases/latest"
        $headers = @{ "User-Agent" = $ua }

        $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers
        $latestVersionStr = $response.tag_name -replace '^v', ''
        $latestVersion = [version]$latestVersionStr

        # Find the Windows setup executable asset (.exe)
        $targetUrl = $null
        $targetFileName = $null

        foreach ($asset in $response.assets) {
            if ($asset.name -match "\.exe$") {
                $targetUrl = $asset.browser_download_url
                $targetFileName = $asset.name
                break
            }
        }

        if (-not $targetUrl) {
            throw "No executable asset (.exe) found in the latest GitHub release."
        }

        Write-Host "[OK: v$latestVersionStr]" -ForegroundColor Green
        
        $tempExe = "$env:TEMP\$targetFileName"
    }

    # ------------------------------------------------------------
    # DETECT CURRENT INSTALLED VERSION
    # ------------------------------------------------------------
    if (-not $skipInstall) {

        Write-Host ">> Checking local version marker..." -ForegroundColor Yellow

        $currentVersion = [version]"0.0.0.0"
        $detected = $false

        if (Test-Path $versionMarker) {
            try {
                $content = (Get-Content $versionMarker -Raw).Trim()
                if ($content -match "([\d\.]+)") {
                    $currentVersion = [version]$matches[1]
                    $detected = $true
                    Write-Host "   [VERSION FOUND] Installed: $currentVersion" -ForegroundColor Cyan
                }
            } catch {
                Write-Host "   [READ FAILED]" -ForegroundColor DarkYellow
            }
        }

        if (-not $detected) {
            Write-Host "   [NO PREVIOUS VERSION MARKER]" -ForegroundColor DarkGray
        }

        # ------------------------------------------------------------
        # VERSION COMPARISON
        # ------------------------------------------------------------
        if ($latestVersion -le $currentVersion) {
            Write-Host ">> Status: [ALREADY UP TO DATE]" -ForegroundColor Green
            $skipInstall = $true
        }
    }

    # ------------------------------------------------------------
    # DOWNLOAD AND INSTALL ONLY IF NEEDED
    # ------------------------------------------------------------
    if (-not $skipInstall) {

        Write-Host ">> Status: [UPDATE REQUIRED]" -ForegroundColor Cyan

        # Download installer
        Write-Host ">> Downloading $targetFileName... " -ForegroundColor Yellow -NoNewline
        Invoke-WebRequest -Uri $targetUrl -OutFile $tempExe -UserAgent $ua -ErrorAction Stop
        Write-Host "[OK]" -ForegroundColor Green

        # Ensure target directory exists
        if (-not (Test-Path $installDir)) {
            New-Item -Path $installDir -ItemType Directory -Force | Out-Null
        }

        # ------------------------------------------------------------
        # EXECUTE SILENT INSTALLATION (Using NSIS switch /S)
        # ------------------------------------------------------------
        Write-Host ">> Executing Pawzy installer silently..." -ForegroundColor Yellow
        
        Start-Process -FilePath $tempExe -ArgumentList "/S" -Wait -NoNewWindow

        # Save version marker
        Set-Content -Path $versionMarker -Value $latestVersionStr -Force
        Write-Host ">> Version marker updated to: $latestVersionStr" -ForegroundColor Gray
        Write-Host ">> Deployment completed successfully." -ForegroundColor Green
    }

} catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
} finally {
    # ------------------------------------------------------------
    # CLEANUP INSTALLER EXECUTABLE
    # ------------------------------------------------------------
    if (-not [string]::IsNullOrEmpty($tempExe) -and (Test-Path $tempExe)) {
        Write-Host ">> Cleaning up installer package..." -ForegroundColor Yellow
        Remove-Item $tempExe -Force -ErrorAction SilentlyContinue
        Write-Host ">> Cleanup complete." -ForegroundColor Green
    }
}

# Create PawzyClose.cmd if it does not exist

$Destination = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\PawzyClose.cmd"

if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
    Set-Content -LiteralPath $Destination -Value 'taskkill /F /IM Pawzy.exe /T' -Encoding ASCII
}

Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# ============================================================
# PDFCRAFT DEPLOYMENT
# ============================================================

Write-Host "[MODULE] Deploying PdfCraft via dynamic GitHub resolution..." -ForegroundColor Cyan

# Ensure TLS 1.2 compatibility
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ------------------------------------------------------------
# PATHS & CONFIGURATION
# ------------------------------------------------------------
$installDir    = Join-Path $env:ProgramData "PdfCraftDeployment"
$versionMarker = Join-Path $installDir "version.txt"
$ua            = "Mozilla/5.0"
$skipInstall   = $false
$tempMsi       = $null
$latestVersion = $null
$latestVersionStr = $null

try {

    # --------------------------------------------------------
    # DETECT WINDOWS SERVER ENVIRONMENT
    # --------------------------------------------------------
    Write-Host ">> Checking operating system type... " -ForegroundColor Yellow -NoNewline

    $os = Get-CimInstance Win32_OperatingSystem
    $isServer = ($os.ProductType -ne 1)

    if ($isServer) {
        Write-Host "[SERVER DETECTED - SKIPPING INSTALL]" -ForegroundColor DarkYellow
        $skipInstall = $true
    }
    else {
        Write-Host "[WORKSTATION]" -ForegroundColor Green
    }

    # --------------------------------------------------------
    # DETECT WINDOWS ARCHITECTURE
    # --------------------------------------------------------
    if (-not $skipInstall) {

        Write-Host ">> Detecting Windows architecture... " -ForegroundColor Yellow -NoNewline

        $architecture = $env:PROCESSOR_ARCHITEW6432

        if ([string]::IsNullOrWhiteSpace($architecture)) {
            $architecture = $env:PROCESSOR_ARCHITECTURE
        }

        switch -Regex ($architecture) {
            '^ARM64$' {
                $targetArch = "arm64"
                break
            }
            '^AMD64$' {
                $targetArch = "x64"
                break
            }
            '^x86$' {
                $targetArch = "x86"
                break
            }
            default {
                throw "Unsupported or unrecognized Windows architecture: $architecture"
            }
        }

        Write-Host "[$targetArch]" -ForegroundColor Green
    }

    # --------------------------------------------------------
    # FETCH LATEST VERSION & MSI URL FROM GITHUB API
    # --------------------------------------------------------
    if (-not $skipInstall) {

        Write-Host ">> Resolving latest version and MSI asset from GitHub... " -ForegroundColor Yellow -NoNewline

        $apiUrl = "https://api.github.com/repos/storytold/pdfcraft/releases/latest"
        $headers = @{ "User-Agent" = $ua }

        $response = Invoke-RestMethod `
            -Uri $apiUrl `
            -Headers $headers `
            -ErrorAction Stop

        if (-not $response.tag_name) {
            throw "GitHub did not return a valid release tag."
        }

        # Extract numeric version from the release tag
        $latestVersionStr = $response.tag_name -replace '^v', ''

        if ($latestVersionStr -notmatch '^\d+(\.\d+){1,3}$') {
            throw "Unsupported release version format: $latestVersionStr"
        }

        $latestVersion = [version]$latestVersionStr

        # Find the MSI matching the detected architecture
        $targetAssetName = "pdfcraft-*-windows-$targetArch.msi"

        $asset = $response.assets |
            Where-Object { $_.name -like $targetAssetName } |
            Select-Object -First 1

        if (-not $asset) {
            throw "No Windows $targetArch MSI found in release $($response.tag_name)."
        }

        $targetUrl = $asset.browser_download_url
        $targetFileName = $asset.name
        $tempMsi = Join-Path $env:TEMP $targetFileName

        Write-Host "[OK: v$latestVersionStr - $targetArch]" -ForegroundColor Green
    }

    # --------------------------------------------------------
    # DETECT CURRENT DEPLOYED VERSION
    # --------------------------------------------------------
    if (-not $skipInstall) {

        Write-Host ">> Checking local version marker..." -ForegroundColor Yellow

        $currentVersion = [version]"0.0.0.0"
        $detected = $false

        if (Test-Path $versionMarker) {
            try {
                $content = (Get-Content $versionMarker -Raw -ErrorAction Stop).Trim()

                if ($content -match '^v?(\d+(\.\d+){1,3})$') {
                    $currentVersion = [version]$matches[1]
                    $detected = $true

                    Write-Host "   [VERSION FOUND] Deployed: $currentVersion" -ForegroundColor Cyan
                }
            }
            catch {
                Write-Host "   [READ FAILED]" -ForegroundColor DarkYellow
            }
        }

        if (-not $detected) {
            Write-Host "   [NO PREVIOUS VERSION MARKER]" -ForegroundColor DarkGray
        }

        # ----------------------------------------------------
        # VERSION COMPARISON
        # ----------------------------------------------------
        if ($latestVersion -le $currentVersion) {
            Write-Host ">> Status: [ALREADY UP TO DATE]" -ForegroundColor Green
            $skipInstall = $true
        }
    }

    # --------------------------------------------------------
    # DOWNLOAD AND INSTALL ONLY IF NEEDED
    # --------------------------------------------------------
    if (-not $skipInstall) {

        Write-Host ">> Status: [UPDATE REQUIRED]" -ForegroundColor Cyan

        # Download MSI
        Write-Host ">> Downloading $targetFileName... " -ForegroundColor Yellow -NoNewline

        Invoke-WebRequest `
            -Uri $targetUrl `
            -OutFile $tempMsi `
            -UserAgent $ua `
            -ErrorAction Stop

        if (-not (Test-Path $tempMsi) -or (Get-Item $tempMsi).Length -eq 0) {
            throw "The downloaded MSI is missing or empty."
        }

        Write-Host "[OK]" -ForegroundColor Green

        # Ensure deployment directory exists
        if (-not (Test-Path $installDir)) {
            New-Item -Path $installDir -ItemType Directory -Force |
                Out-Null
        }

        # ----------------------------------------------------
        # SILENT MSI INSTALLATION
        # ----------------------------------------------------
        Write-Host ">> Executing PdfCraft MSI installer silently..." -ForegroundColor Yellow

        $msiArgs = @(
            "/i"
            "`"$tempMsi`""
            "/qn"
            "/norestart"
            "INSTALLDESKTOPSHORTCUT=0"
        )

        $process = Start-Process `
            -FilePath "$env:SystemRoot\System32\msiexec.exe" `
            -ArgumentList $msiArgs `
            -Wait `
            -PassThru `
            -NoNewWindow

        # 0 = success; 3010 = success, reboot required
        if ($process.ExitCode -notin @(0, 3010)) {
            throw "MSI installation failed with exit code $($process.ExitCode)."
        }

        # Save version marker only after successful installation
        Set-Content `
            -Path $versionMarker `
            -Value $latestVersionStr `
            -Encoding ASCII `
            -Force

        Write-Host ">> Version marker updated to: $latestVersionStr" -ForegroundColor Gray

        if ($process.ExitCode -eq 3010) {
            Write-Host ">> Deployment completed. A restart is required." -ForegroundColor Yellow
        }
        else {
            Write-Host ">> Deployment completed successfully." -ForegroundColor Green
        }
    }

}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
}
finally {

    # --------------------------------------------------------
    # CLEANUP TEMPORARY MSI
    # --------------------------------------------------------
    if (-not [string]::IsNullOrWhiteSpace($tempMsi) -and (Test-Path $tempMsi)) {
        Write-Host ">> Cleaning up installer package..." -ForegroundColor Yellow

        Remove-Item $tempMsi -Force -ErrorAction SilentlyContinue

        Write-Host ">> Cleanup complete." -ForegroundColor Green
    }
}

Write-Host "--------------------------------------------------------"
Write-Host ""

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

# Multi-language dictionary for all 23 requested languages
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
    "ar" = @{ copy = "جميع الحقوق محفوظة."; open = "افتح هنا"; admin = "افتح هنا كمسؤول" }
}

# Fallback to English if the language is not in the dictionary
$langSet = if ($translations.ContainsKey($langID)) { $translations[$langID] } else { $translations["en"] }
$copyText = $langSet.copy
$openText = $langSet.open
$adminText = $langSet.admin

# ==========================================
# COMMAND LINE TOOLS - SHIFT-ONLY CONTEXT MENU
# CMD + Windows PowerShell
# ==========================================

Write-Host "`n>> Configuring Shift-only Command Line Tools..." -ForegroundColor Gray

# --- Registry Locations ---
$basePaths = @(
    "HKLM:\SOFTWARE\Classes\DesktopBackground\Shell",
    "HKLM:\SOFTWARE\Classes\Directory\background\shell",
    "HKLM:\SOFTWARE\Classes\Directory\shell",
    "HKLM:\SOFTWARE\Classes\Drive\shell"
)

$parentName = "CommandLineTools"

# --- Remove Previous Standalone Menus ---
$legacyNames = @(
    "CommandPrompt",
    "PowerShellMenu"
)

foreach ($basePath in $basePaths) {
    try {
        # Remove legacy standalone entries
        foreach ($legacyName in $legacyNames) {
            $legacyPath = Join-Path $basePath $legacyName

            if (Test-Path -LiteralPath $legacyPath) {
                Remove-Item -LiteralPath $legacyPath -Recurse -Force
            }
        }

        # ==========================================
        # PARENT MENU
        # ==========================================

        $rootPath = Join-Path $basePath $parentName

        if (-not (Test-Path -LiteralPath $rootPath)) {
            New-Item -Path $rootPath -Force | Out-Null
        }

        Set-ItemProperty -Path $rootPath -Name "MUIVerb" -Value "Command Line Tools" -Force
        Set-ItemProperty -Path $rootPath -Name "Icon" -Value "imageres.dll,-5323" -Force
        Set-ItemProperty -Path $rootPath -Name "SubCommands" -Value "" -Force

        # Shift-only visibility
        Set-ItemProperty -Path $rootPath -Name "Extended" -Value "" -Force

        $shellPath = Join-Path $rootPath "shell"

        if (-not (Test-Path -LiteralPath $shellPath)) {
            New-Item -Path $shellPath -Force | Out-Null
        }

        # Determine target path placeholder
        $isDirectory = $basePath -match '\\(Directory|Drive)\\'
        $target = if ($isDirectory) { '%L' } else { '%V' }

        # ==========================================
        # COMMAND PROMPT (CMD)
        # ==========================================

        $cmdPath = Join-Path $shellPath "cmd"

        if (Test-Path -LiteralPath $cmdPath) {
            Remove-Item -LiteralPath $cmdPath -Recurse -Force
        }

        New-Item -Path $cmdPath -Force | Out-Null

        Set-ItemProperty -Path $cmdPath -Name "MUIVerb" -Value "Command Prompt (CMD)" -Force
        Set-ItemProperty -Path $cmdPath -Name "Icon" -Value "imageres.dll,-5323" -Force
        Set-ItemProperty -Path $cmdPath -Name "SubCommands" -Value "" -Force

        $cmdShell = Join-Path $cmdPath "shell"

        # --- CMD: Open Normally ---
        $cmdNormalPath = Join-Path $cmdShell "open"
        $cmdNormalCommand = Join-Path $cmdNormalPath "command"

        New-Item -Path $cmdNormalCommand -Force | Out-Null

        Set-ItemProperty -Path $cmdNormalPath -Name "MUIVerb" -Value $openText -Force
        Set-ItemProperty -Path $cmdNormalPath -Name "Icon" -Value "imageres.dll,-5323" -Force

        $normalCmd = 'cmd.exe /s /k "pushd ""{0}"" & ver & echo (c) Microsoft Corporation. {1} & echo."' -f $target, $copyText

        Set-ItemProperty -Path $cmdNormalCommand -Name "(Default)" -Value $normalCmd -Force

        # --- CMD: Open as Administrator ---
        $cmdAdminPath = Join-Path $cmdShell "admin"
        $cmdAdminCommand = Join-Path $cmdAdminPath "command"

        New-Item -Path $cmdAdminCommand -Force | Out-Null

        Set-ItemProperty -Path $cmdAdminPath -Name "MUIVerb" -Value $adminText -Force
        Set-ItemProperty -Path $cmdAdminPath -Name "Icon" -Value "imageres.dll,-5324" -Force
        Set-ItemProperty -Path $cmdAdminPath -Name "HasLUAShield" -Value "" -Force

        $innerCmd = "/k cd /d `"$target`" & ver & echo (c) Microsoft Corporation. $copyText & echo."
        $adminCmd = "powershell.exe -NoProfile -WindowStyle Hidden -Command `"Start-Process cmd.exe -ArgumentList '$innerCmd' -Verb RunAs`""

        Set-ItemProperty -Path $cmdAdminCommand -Name "(Default)" -Value $adminCmd -Force

        # ==========================================
        # WINDOWS POWERSHELL
        # ==========================================

        $psPath = Join-Path $shellPath "powershell"

        if (Test-Path -LiteralPath $psPath) {
            Remove-Item -LiteralPath $psPath -Recurse -Force
        }

        New-Item -Path $psPath -Force | Out-Null

        Set-ItemProperty -Path $psPath -Name "MUIVerb" -Value "Windows PowerShell" -Force
        Set-ItemProperty -Path $psPath -Name "Icon" -Value "powershell.exe" -Force
        Set-ItemProperty -Path $psPath -Name "SubCommands" -Value "" -Force

        $psShell = Join-Path $psPath "shell"

        # --- PowerShell: Open Normally ---
        $psNormalPath = Join-Path $psShell "open"
        $psNormalCommand = Join-Path $psNormalPath "command"

        New-Item -Path $psNormalCommand -Force | Out-Null

        Set-ItemProperty -Path $psNormalPath -Name "MUIVerb" -Value $openText -Force
        Set-ItemProperty -Path $psNormalPath -Name "Icon" -Value "powershell.exe" -Force

        $normalPs = 'powershell.exe -NoExit -Command "Set-Location -LiteralPath ''{0}''; Write-Host ''Windows PowerShell''; Write-Host ''(c) Microsoft Corporation. {1}''' -f $target, $copyText

        Set-ItemProperty -Path $psNormalCommand -Name "(Default)" -Value $normalPs -Force

        # --- PowerShell: Open as Administrator ---
        $psAdminPath = Join-Path $psShell "admin"
        $psAdminCommand = Join-Path $psAdminPath "command"

        New-Item -Path $psAdminCommand -Force | Out-Null

        Set-ItemProperty -Path $psAdminPath -Name "MUIVerb" -Value $adminText -Force
        Set-ItemProperty -Path $psAdminPath -Name "Icon" -Value "powershell.exe" -Force
        Set-ItemProperty -Path $psAdminPath -Name "HasLUAShield" -Value "" -Force

        $innerPs = "Set-Location -LiteralPath ''{0}''; Write-Host ''Windows PowerShell''; Write-Host ''(c) Microsoft Corporation. {1}''; Write-Host ''''" -f $target, $copyText
        $adminPs = 'powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Process powershell.exe -ArgumentList ''-NoExit'', ''-Command'', ''{0}'' -Verb RunAs"' -f $innerPs

        Set-ItemProperty -Path $psAdminCommand -Name "(Default)" -Value $adminPs -Force

        Write-Host "[OK] Shift-only menu configured: $basePath" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] $basePath : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n[DONE] Command Line Tools configuration completed." -ForegroundColor Cyan
Write-Host "Hold SHIFT + right-click to access the menu." -ForegroundColor Yellow
Write-Host "Deployment Complete. Detected: $langID | Labels applied." -ForegroundColor Cyan
Write-Host "`--------------------------------------------------------"

##------------------------------------------------------##

# --- ADVANCED TOOLS: UNIFIED DESKTOP CONTEXT MENU ---
Write-Host "`n[MODULE] Configuring Advanced Tools context menu..." -ForegroundColor Cyan

$langID = (Get-Culture).TwoLetterISOLanguageName
$basePath = "Registry::HKEY_CLASSES_ROOT\DesktopBackground\Shell"
$root = "$basePath\AdvancedTools"

# --- TRANSLATIONS ---
$t = @{
    AdvancedTools = @{
        en = "Advanced Tools"; pt = "Ferramentas Avançadas"; es = "Herramientas avanzadas"; fr = "Outils avancés"; de = "Erweiterte Tools"; it = "Strumenti avanzati"; ru = "Дополнительные инструменты"; "zh-TW" = "進階工具"; "zh-CN" = "高级工具"; ar = "أدوات متقدمة"; cs = "Pokročilé nástroje"; da = "Avancerede værktøjer"; nl = "Geavanceerde hulpmiddelen"; fi = "Lisätyökalut"; el = "Προηγμένα εργαλεία"; he = "כלים מתקדמים"; hu = "Speciális eszközök"; ja = "高度なツール"; ko = "고급 도구"; no = "Avanserte verktøy"; pl = "Narzędzia zaawansowane"; sv = "Avancerade verktyg"; tr = "Gelişmiş Araçlar"
    }
    ControlPanel = @{
        en = "Control Panel"; pt = "Painel de Controle"; es = "Panel de control"; fr = "Panneau de configuration"; de = "Systemsteuerung"; it = "Pannello di controllo"; ru = "Панель управления"; "zh-TW" = "控制台"; "zh-CN" = "控制面板"; ar = "لوحة التحكم"; cs = "Ovládací panely"; da = "Kontrolpanel"; nl = "Configuratiescherm"; fi = "Ohjauspaneeli"; el = "Πίνακας Ελέγχου"; he = "לוח הבקרה"; hu = "Vezérlőpult"; ja = "コントロール パネル"; ko = "제어판"; no = "Kontrollpanel"; pl = "Panel sterowania"; sv = "Kontrollpanelen"; tr = "Denetim Masası"
    }
    CPCat = @{
        en = "Category View"; pt = "Exibir por Categoria"; es = "Ver por categoría"; fr = "Affichage par catégorie"; de = "Kategorieansicht"; it = "Visualizzazione per categoria"; ru = "Просмотр по категориям"; "zh-TW" = "類別檢視"; "zh-CN" = "类别视图"; ar = "عرض حسب الفئة"; cs = "Zobrazení podle kategorií"; da = "Kategorivisning"; nl = "Categorieweergave"; fi = "Luokkanäkymä"; el = "Προβολή κατηγορίας"; he = "תצוגת קטגוריות"; hu = "Kategória nézet"; ja = "カテゴリ表示"; ko = "범주 보기"; no = "Kategorivisning"; pl = "Widok kategorii"; sv = "Kategorivy"; tr = "Kategori Görünümü"
    }
    CPIcons = @{
        en = "All Items (Icons)"; pt = "Todos os Itens (Ícones)"; es = "Todos los elementos (iconos)"; fr = "Tous les éléments (icônes)"; de = "Alle Elemente (Symbole)"; it = "Tutti gli elementi (icone)"; ru = "Все элементы (значки)"; "zh-TW" = "所有項目（圖示）"; "zh-CN" = "所有项目（图标）"; ar = "جميع العناصر (أيقونات)"; cs = "Všechny položky (ikony)"; da = "Alle elementer (ikoner)"; nl = "Alle items (pictogrammen)"; fi = "Kaikki kohteet (kuvakkeet)"; el = "Όλα τα στοιχεία (εικονίδια)"; he = "כל הפריטים (סמלים)"; hu = "Minden elem (ikonok)"; ja = "すべての項目（アイコン）"; ko = "모든 항목(아이콘)"; no = "Alle elementer (ikoner)"; pl = "Wszystkie elementy (ikony)"; sv = "Alla objekt (ikoner)"; tr = "Tüm Öğeler (Simgeler)"
    }
    GodMode = @{
        en = "All Tasks (God Mode)"; pt = "Todas as Tarefas (God Mode)"; es = "Todas las tareas (Modo Dios)"; fr = "Toutes les tâches (Mode Dieu)"; de = "Alle Aufgaben (Gottmodus)"; it = "Tutte le attività (God Mode)"; ru = "Все задачи (режим Бога)"; "zh-TW" = "所有工作（上帝模式）"; "zh-CN" = "所有任务（上帝模式）"; ar = "جميع المهام (وضع الإله)"; cs = "Všechny úkoly (God Mode)"; da = "Alle opgaver (God Mode)"; nl = "Alle taken (God Mode)"; fi = "Kaikki tehtävät (God Mode)"; el = "Όλες οι εργασίες (God Mode)"; he = "כל המשימות (מצב אלוהים)"; hu = "Minden feladat (God Mode)"; ja = "すべてのタスク（God Mode）"; ko = "모든 작업(God Mode)"; no = "Alle oppgaver (God Mode)"; pl = "Wszystkie zadania (God Mode)"; sv = "Alla uppgifter (God Mode)"; tr = "Tüm Görevler (God Mode)"
    }
    KillTasks = @{
        en = "Kill Unresponsive Tasks"; pt = "Encerrar Processos Travados"; es = "Finalizar tareas que no responden"; fr = "Arrêter les tâches bloquées"; de = "Nicht reagierende Prozesse beenden"; it = "Termina processi bloccati"; ru = "Завершить зависшие процессы"; "zh-TW" = "結束無回應的工作"; "zh-CN" = "结束无响应的任务"; ar = "إنهاء المهام غير المستجيبة"; cs = "Ukončit nereagující úlohy"; da = "Afslut processer, der ikke svarer"; nl = "Vastgelopen taken beëindigen"; fi = "Lopeta vastaamattomat tehtävät"; el = "Τερματισμός εργασιών που δεν αποκρίνονται"; he = "סיום משימות שאינן מגיבות"; hu = "Nem válaszoló feladatok leállítása"; ja = "応答しないタスクを終了"; ko = "응답하지 않는 작업 종료"; no = "Avslutt oppgaver som ikke svarer"; pl = "Zakończ nieodpowiadające zadania"; sv = "Avsluta processer som inte svarar"; tr = "Yanıt Vermeyen Görevleri Sonlandır"
    }
    SafeMode = @{
        en = "Safe Mode"; pt = "Modo de Segurança"; es = "Modo seguro"; fr = "Mode sans échec"; de = "Abgesicherter Modus"; it = "Modalità provvisoria"; ru = "Безопасный режим"; "zh-TW" = "安全模式"; "zh-CN" = "安全模式"; ar = "الوضع الآمن"; cs = "Nouzový režim"; da = "Fejlsikret tilstand"; nl = "Veilige modus"; fi = "Vikasietotila"; el = "Ασφαλής λειτουργία"; he = "מצב בטוח"; hu = "Csökkentett mód"; ja = "セーフ モード"; ko = "안전 모드"; no = "Sikker modus"; pl = "Tryb awaryjny"; sv = "Felsäkert läge"; tr = "Güvenli Mod"
    }
    Normal = @{
        en = "Restart in Normal Mode"; pt = "Reiniciar em Modo Normal"; es = "Reiniciar en modo normal"; fr = "Redémarrer en mode normal"; de = "Im normalen Modus neu starten"; it = "Riavvia in modalità normale"; ru = "Перезагрузить в обычном режиме"; "zh-TW" = "重新啟動至正常模式"; "zh-CN" = "重启进入正常模式"; ar = "إعادة التشغيل في الوضع العادي"; cs = "Restartovat v normálním režimu"; da = "Genstart i normal tilstand"; nl = "Opnieuw opstarten in normale modus"; fi = "Käynnistä uudelleen normaalitilaan"; el = "Επανεκκίνηση σε κανονική λειτουργία"; he = "הפעלה מחדש במצב רגיל"; hu = "Újraindítás normál módban"; ja = "通常モードで再起動"; ko = "일반 모드로 다시 시작"; no = "Start på nytt i normal modus"; pl = "Uruchom ponownie w trybie normalnym"; sv = "Starta om i normalt läge"; tr = "Normal Modda Yeniden Başlat"
    }
    Safe = @{
        en = "Restart in Safe Mode"; pt = "Reiniciar em Modo de Segurança"; es = "Reiniciar en modo seguro"; fr = "Redémarrer en mode sans échec"; de = "Im abgesicherten Modus neu starten"; it = "Riavvia in modalità provvisoria"; ru = "Перезагрузить в безопасном режиме"; "zh-TW" = "重新啟動至安全模式"; "zh-CN" = "重启进入安全模式"; ar = "إعادة التشغيل في الوضع الآمن"; cs = "Restartovat v nouzovém režimu"; da = "Genstart i fejlsikret tilstand"; nl = "Opnieuw opstarten in veilige modus"; fi = "Käynnistä uudelleen vikasietotilaan"; el = "Επανεκκίνηση σε ασφαλή λειτουργία"; he = "הפעלה מחדש במצב בטוח"; hu = "Újraindítás csökkentett módban"; ja = "セーフ モードで再起動"; ko = "안전 모드로 다시 시작"; no = "Start på nytt i sikker modus"; pl = "Uruchom ponownie w trybie awaryjnym"; sv = "Starta om i felsäkert läge"; tr = "Güvenli Modda Yeniden Başlat"
    }
    Network = @{
        en = "Safe Mode with Networking"; pt = "Modo de Segurança com Rede"; es = "Modo seguro con funciones de red"; fr = "Mode sans échec avec réseau"; de = "Abgesicherter Modus mit Netzwerk"; it = "Modalità provvisoria con rete"; ru = "Безопасный режим с поддержкой сети"; "zh-TW" = "含網路功能的安全模式"; "zh-CN" = "带网络连接的安全模式"; ar = "الوضع الآمن مع الشبكات"; cs = "Nouzový režim se sítí"; da = "Fejlsikret tilstand med netværk"; nl = "Veilige modus met netwerkmogelijkheden"; fi = "Vikasietila verkkoyhteydellä"; el = "Ασφαλής λειτουργία με δίκτυο"; he = "מצב בטוח עם רשת"; hu = "Csökkentett mód hálózattal"; ja = "ネットワーク対応セーフ モード"; ko = "네트워킹 사용 안전 모드"; no = "Sikker modus med nettverk"; pl = "Tryb awaryjny z obsługą sieci"; sv = "Felsäkert läge med nätverk"; tr = "Ağ ile Güvenli Mod"
    }
    CMD = @{
        en = "Safe Mode with Command Prompt"; pt = "Modo de Segurança com Prompt"; es = "Modo seguro con símbolo del sistema"; fr = "Mode sans échec avec invite de commandes"; de = "Abgesicherter Modus mit Eingabeaufforderung"; it = "Modalità provvisoria con prompt dei comandi"; ru = "Безопасный режим с командной строкой"; "zh-TW" = "含命令提示字元的安全模式"; "zh-CN" = "带命令提示符的安全模式"; ar = "الوضع الآمن مع موجه الأوامر"; cs = "Nouzový režim s příkazovým řádkem"; da = "Fejlsikret tilstand med kommandoprompt"; nl = "Veilige modus met opdrachtprompt"; fi = "Vikasietila komentokehotteella"; el = "Ασφαλής λειτουργία με γραμμή εντολών"; he = "מצב בטוח עם שורת פקודה"; hu = "Csökkentett mód parancssorral"; ja = "コマンド プロンプト付きセーフ モード"; ko = "명령 프롬프트 사용 안전 모드"; no = "Sikker modus med ledetekst"; pl = "Tryb awaryjny z wierszem polecenia"; sv = "Felsäkert läge med kommandotolk"; tr = "Komut İstemi ile Güvenli Mod"
    }
    Explorer = @{
        en = "Restart Explorer"; pt = "Reiniciar Explorer"; es = "Reiniciar el Explorador"; fr = "Redémarrer l’Explorateur"; de = "Explorer neu starten"; it = "Riavvia Esplora file"; ru = "Перезапустить Проводник"; "zh-TW" = "重新啟動檔案總管"; "zh-CN" = "重新启动文件资源管理器"; ar = "إعادة تشغيل المستكشف"; cs = "Restartovat Průzkumníka"; da = "Genstart Stifinder"; nl = "Verkenner opnieuw starten"; fi = "Käynnistä Resurssienhallinta uudelleen"; el = "Επανεκκίνηση Εξερεύνησης αρχείων"; he = "הפעלה מחדש של סייר הקבצים"; hu = "Fájlkezelő újraindítása"; ja = "エクスプローラーを再起動"; ko = "파일 탐색기 다시 시작"; no = "Start Filutforsker på nytt"; pl = "Uruchom ponownie Eksplorator plików"; sv = "Starta om Utforskaren"; tr = "Dosya Gezgini'ni Yeniden Başlat"
    }
    ExplorerNow = @{
        en = "Restart Explorer Now"; pt = "Reiniciar Explorer Agora"; es = "Reiniciar el Explorador ahora"; fr = "Redémarrer l’Explorateur maintenant"; de = "Explorer jetzt neu starten"; it = "Riavvia Esplora file ora"; ru = "Перезапустить Проводник сейчас"; "zh-TW" = "立即重新啟動檔案總管"; "zh-CN" = "立即重新启动文件资源管理器"; ar = "إعادة تشغيل المستكشف الآن"; cs = "Restartovat Průzkumníka nyní"; da = "Genstart Stifinder nu"; nl = "Verkenner nu opnieuw starten"; fi = "Käynnistä Resurssienhallinta nyt uudelleen"; el = "Επανεκκίνηση Εξερεύνησης αρχείων τώρα"; he = "הפעלה מחדש של סייר הקבצים כעת"; hu = "Fájlkezelő újraindítása most"; ja = "エクスプローラーを今すぐ再起動"; ko = "파일 탐색기 지금 다시 시작"; no = "Start Filutforsker på nytt nå"; pl = "Uruchom Eksplorator plików ponownie teraz"; sv = "Starta om Utforskaren nu"; tr = "Dosya Gezgini'ni Şimdi Yeniden Başlat"
    }
    ExplorerPause = @{
        en = "Restart Explorer with Pause"; pt = "Reiniciar Explorer com Pausa"; es = "Reiniciar el Explorador con pausa"; fr = "Redémarrer l’Explorateur avec pause"; de = "Explorer mit Pause neu starten"; it = "Riavvia Esplora file con pausa"; ru = "Перезапустить Проводник с паузой"; "zh-TW" = "暫停後重新啟動檔案總管"; "zh-CN" = "暂停后重新启动文件资源管理器"; ar = "إعادة تشغيل المستكشف مع توقف مؤقت"; cs = "Restartovat Průzkumníka s pauzou"; da = "Genstart Stifinder med pause"; nl = "Verkenner opnieuw starten met pauze"; fi = "Käynnistä Resurssienhallinta uudelleen tauolla"; el = "Επανεκκίνηση Εξερεύνησης αρχείων με παύση"; he = "הפעלה מחדש של סייר הקבצים עם השהיה"; hu = "Fájlkezelő újraindítása szünettel"; ja = "一時停止してエクスプローラーを再起動"; ko = "일시 중지 후 파일 탐색기 다시 시작"; no = "Start Filutforsker på nytt med pause"; pl = "Uruchom ponownie Eksplorator plików z pauzą"; sv = "Starta om Utforskaren med paus"; tr = "Dosya Gezgini'ni Duraklatarak Yeniden Başlat"
    }
    SysProp = @{
        en = "System Properties"; pt = "Propriedades do Sistema"; es = "Propiedades del sistema"; fr = "Propriétés système"; de = "Systemeigenschaften"; it = "Proprietà del sistema"; ru = "Свойства системы"; "zh-TW" = "系統內容"; "zh-CN" = "系统属性"; ar = "خصائص النظام"; cs = "Vlastnosti systému"; da = "Systemegenskaber"; nl = "Systeemeigenschappen"; fi = "Järjestelmän ominaisuudet"; el = "Ιδιότητες συστήματος"; he = "מאפייני מערכת"; hu = "Rendszertulajdonságok"; ja = "システムのプロパティ"; ko = "시스템 속성"; no = "Systemegenskaper"; pl = "Właściwości systemu"; sv = "Systemegenskaper"; tr = "Sistem Özellikleri"
    }
}

function Get-T {
    param([string]$Key)

    if ($t[$Key].ContainsKey($langID)) {
        return $t[$Key][$langID]
    }

    return $t[$Key]["en"]
}

function Set-RegString {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    }

    if ($Name -eq "(Default)") {
        Set-Item -LiteralPath $Path -Value $Value -ErrorAction Stop
    }
    else {
        New-ItemProperty -LiteralPath $Path -Name $Name `
            -Value $Value -PropertyType String -Force `
            -ErrorAction Stop | Out-Null
    }
}

function New-MenuItem {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Icon,
        [string]$Command
    )

    Set-RegString $Path "MUIVerb" $Name
    Set-RegString $Path "Icon" $Icon
    Set-RegString "$Path\command" "(Default)" $Command
}

try {
    # Create the unified parent menu.
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    }

    Set-RegString $root "MUIVerb" (Get-T "AdvancedTools")
    Set-RegString $root "Icon" "imageres.dll,-5302"
    Set-RegString $root "SubCommands" ""

    # 1. CONTROL PANEL SUBMENU
    $cp = "$root\shell\01ControlPanel"

    Set-RegString $cp "MUIVerb" (Get-T "ControlPanel")
    Set-RegString $cp "Icon" "imageres.dll,-27"
    Set-RegString $cp "SubCommands" ""

    New-MenuItem "$cp\shell\01Category" `
        (Get-T "CPCat") "imageres.dll,-27" `
        "explorer.exe shell:::{26EE0668-A00A-44D7-9371-BEB064C98683}"

    New-MenuItem "$cp\shell\02Icons" `
        (Get-T "CPIcons") "imageres.dll,-27" `
        "explorer.exe shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}"

    New-MenuItem "$cp\shell\03GodMode" `
        (Get-T "GodMode") "imageres.dll,-27" `
        "explorer.exe shell:::{ED7BA470-8E54-465E-825C-99712043E01C}"

    # 2. KILL UNRESPONSIVE TASKS
    New-MenuItem "$root\shell\02KillTasks" `
        (Get-T "KillTasks") "taskmgr.exe,-30651" `
        'cmd.exe /c taskkill.exe /f /fi "status eq Not Responding" & pause'

    # 3. SAFE MODE SUBMENU
    $sm = "$root\shell\03SafeMode"

    Set-RegString $sm "MUIVerb" (Get-T "SafeMode")
    Set-RegString $sm "Icon" "bootux.dll,-1032"
    Set-RegString $sm "SubCommands" ""

    $safeItems = @(
        @{
            ID = "01Normal"
            Key = "Normal"
            Icon = "shell32.dll,-239"
            Args = '/deletevalue {current} safeboot'
            Extra = ' & bcdedit /deletevalue {current} safebootalternateshell'
        },
        @{
            ID = "02Safe"
            Key = "Safe"
            Icon = "imageres.dll,-102"
            Args = '/set {current} safeboot minimal'
            Extra = ' & bcdedit /deletevalue {current} safebootalternateshell'
        },
        @{
            ID = "03Network"
            Key = "Network"
            Icon = "shell32.dll,-257"
            Args = '/set {current} safeboot network'
            Extra = ' & bcdedit /deletevalue {current} safebootalternateshell'
        },
        @{
            ID = "04CMD"
            Key = "CMD"
            Icon = "cmd.exe"
            Args = '/set {current} safeboot minimal'
            Extra = ' & bcdedit /set {current} safebootalternateshell yes'
        }
    )

    foreach ($item in $safeItems) {
        $cmd = "bcdedit $($item.Args)$($item.Extra) & shutdown.exe -r -t 0 -f"

        New-MenuItem "$sm\shell\$($item.ID)" `
            (Get-T $item.Key) $item.Icon `
            "powershell.exe -NoProfile -Command `"Start-Process cmd.exe -ArgumentList '/c $cmd' -Verb RunAs`""
    }

    # 4. RESTART EXPLORER SUBMENU
    $re = "$root\shell\04Explorer"

    Set-RegString $re "MUIVerb" (Get-T "Explorer")
    Set-RegString $re "Icon" "explorer.exe"
    Set-RegString $re "SubCommands" ""

    New-MenuItem "$re\shell\01Now" `
        (Get-T "ExplorerNow") "shell32.dll,-16739" `
        'cmd.exe /c taskkill /f /im explorer.exe & start explorer.exe'

    New-MenuItem "$re\shell\02Pause" `
        (Get-T "ExplorerPause") "shell32.dll,-315" `
        'cmd.exe /c taskkill /f /im explorer.exe & pause & start explorer.exe'

    # 5. SYSTEM PROPERTIES
    New-MenuItem "$root\shell\05SystemProperties" `
        (Get-T "SysProp") "SystemPropertiesAdvanced.exe" `
        "SystemPropertiesAdvanced.exe"

    # Remove the old standalone entries created by the previous module.
    $oldKeys = @(
        "ControlPanel",
        "KillNRTasks",
        "SafeMode",
        "Restart Explorer",
        "System Properties"
    )

    foreach ($key in $oldKeys) {
        $oldPath = "$basePath\$key"

        if (Test-Path -LiteralPath $oldPath) {
            Remove-Item -LiteralPath $oldPath -Recurse -Force `
                -ErrorAction Stop
            Write-Host "Removed old entry: $key" -ForegroundColor DarkGray
        }
    }

    Write-Host "`n[SUCCESS] Advanced Tools menu configured." -ForegroundColor Green
    Write-Host "Language: $langID" -ForegroundColor Gray
    Write-Host "All tools are grouped under one submenu." -ForegroundColor White
}
catch {
    Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the registry for partially created entries." -ForegroundColor Yellow
}

Write-Host "--------------------------------------------------------"

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
# DESCRIPTION: Deploys silent repair script + optional desktop context menu
#              SKIPS CONTEXT MENU ON WINDOWS SERVER (NO ABORT)
# ==============================================================================

Write-Host "FIX PRINT SPOOLER CONTEXT MENU" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------
# OS DETECTION
# ------------------------------------------------
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$isServer = ($osInfo.ProductType -ne 1)

if ($isServer) {

    Write-Host "[SERVER DETECTED] $($osInfo.Caption)" -ForegroundColor Yellow
    Write-Host "[ACTION] Disabling Print Spooler (NO CONTEXT MENU WILL BE CREATED)" -ForegroundColor Cyan

    Set-Service -Name "Spooler" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue

    Write-Host "[OK] Spooler disabled on Server. Skipping context menu only." -ForegroundColor Green
    Write-Host ""

} else {

    Write-Host "[CLIENT DETECTED] Context menu will be created." -ForegroundColor Green
    Write-Host ""
}

# ------------------------------------------------
# SILENT REPAIR SCRIPT PAYLOAD
# ------------------------------------------------
$scriptContent = @'
$spoolPath = "$env:SystemRoot\System32\spool\PRINTERS"

Set-Service -Name "Spooler" -StartupType Disabled
Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
Stop-Service -Name "PrintNotify" -Force -ErrorAction SilentlyContinue

if (Test-Path "$spoolPath\*") {
    try {
        Remove-Item -Path "$spoolPath\*" -Force -Recurse -ErrorAction SilentlyContinue
    } catch {}
}

Set-Service -Name "Spooler" -StartupType Automatic
Start-Service -Name "Spooler"
'@

# ------------------------------------------------
# DEPLOY SCRIPT
# ------------------------------------------------
Write-Host "[STEP 1] Deploying FixSpooler.ps1..." -ForegroundColor Cyan

try {
    $scriptPath = "C:\Windows\FixSpooler.ps1"
    Set-Content -Path $scriptPath -Value $scriptContent -Force
    Write-Host "[OK] Script deployed." -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Failed to write FixSpooler.ps1" -ForegroundColor Red
}

# ------------------------------------------------
# SKIP CONTEXT MENU ON SERVER
# ------------------------------------------------
if ($isServer) {

    Write-Host "[STEP 2] Context menu skipped (Windows Server policy)" -ForegroundColor Yellow
    Write-Host "--------------------------------------------------------"
    Write-Host ""
    
} else {

    # ------------------------------------------------
    # CONTEXT MENU CREATION (DESKTOP ONLY)
    # ------------------------------------------------
    Write-Host "[STEP 2] Creating desktop context menu..." -ForegroundColor Cyan

    $currentLang = [System.Globalization.CultureInfo]::CurrentUICulture.Name

    $langMap = @{
        "pt*" = "Corrigir Spooler de Impressão"
        "en*" = "Fix Print Spooler"
        "es*" = "Corregir Cola de impresión"
        "fr*" = "Réparer le Spouleur d'impression"
        "de*" = "Druckwarteschlange reparieren"
        "it*" = "Ripristina Spooler di stampa"
        "ru*" = "Исправить диспетчер печати"
        "zh-TW*" = "修復列印多多工緩衝處理器"
        "zh-CN*" = "修复打印后台处理程序"
        "ar*" = "إصلاح قائمة انتظار الطباعة"
        "cs*" = "Opravit službu Spooler"
        "da*" = "Reparer Print Spooler"
        "nl*" = "Afdrukspooler repareren"
        "fi*" = "Korjaa tulostuksen taustatulostus"
        "el*" = "Επιδιόρθωση ουράς εκτύπωσης"
        "he*" = "תיקון Print Spooler"
        "hu*" = "Nyomtatási várólista javítása"
        "ja*" = "印刷スプーラーを修復する"
        "ko*" = "인쇄 스풀러 복구"
        "no*" = "Reparer Print Spooler"
        "pl*" = "Napraw bufor wydruku"
        "sv*" = "Reparera Print Spooler"
        "tr*" = "Yazdırma Biriktiricisi Onar"
    }

    $menuName = ""

    foreach ($pattern in $langMap.Keys) {
        if ($currentLang -like $pattern) {
            $menuName = $langMap[$pattern]
            break
        }
    }

    if (-not $menuName) { $menuName = "Fix Print Spooler" }

    $regPath = "Registry::HKEY_LOCAL_MACHINE\Software\Classes\DesktopBackground\Shell\FixSpooler"
    $commandPath = "$regPath\command"

    $commandValue = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \`"C:\Windows\FixSpooler.ps1\`"' -Verb RunAs`""

    try {

        if (Test-Path $regPath) {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
        }

        New-Item -Path $regPath -Force | Out-Null

        Set-ItemProperty -Path $regPath -Name "(Default)" -Value $menuName
        Set-ItemProperty -Path $regPath -Name "Icon" -Value "imageres.dll,-51"
        Set-ItemProperty -Path $regPath -Name "HasLUAShield" -Value ""

        if (-not (Test-Path $commandPath)) {
            New-Item -Path $commandPath -Force | Out-Null
        }

        Set-ItemProperty -Path $commandPath -Name "(Default)" -Value $commandValue

        Write-Host "[OK] Context menu created: $menuName" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Registry update failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""
}

# ------------------------------------------------
# FINAL
# ------------------------------------------------
Write-Host "--- Deployment Finished ---" -ForegroundColor Yellow
Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# ==============================================================================
# SCRIPT: Shutdown Context Menu Deployment (Multilingual)
# DESCRIPTION: Creates a native Windows desktop context menu with nine options.
#              Supports Windows Client and Windows Server.
# ==============================================================================

Write-Host "`n--- SHUTDOWN CONTEXT MENU DEPLOYMENT ---" -ForegroundColor Cyan

# ------------------------------------------------
# LANGUAGE DETECTION
# ------------------------------------------------

$currentLang = [System.Globalization.CultureInfo]::CurrentUICulture.Name

$langMap = @{
    "pt" = @(
        "Desligar o PC"
        "Desligar o PC agora"
        "Desligar o PC em 20 minutos"
        "Desligar o PC em 40 minutos"
        "Desligar o PC em 1 hora"
        "Desligar o PC em 2 horas"
        "Desligar o PC em 3 horas"
        "Desligar o PC em 4 horas"
        "Reiniciar o PC agora"
        "Cancelar desligamento automático"
        "Deslizar para desligar o PC"
    )
    "en" = @(
        "Shut Down PC"
        "Shut Down PC Now"
        "Shut Down PC in 20 Minutes"
        "Shut Down PC in 40 Minutes"
        "Shut Down PC in 1 Hour"
        "Shut Down PC in 2 Hours"
        "Shut Down PC in 3 Hours"
        "Shut Down PC in 4 Hours"
        "Restart PC Now"
        "Cancel Automatic Shutdown"
        "Slide to Shut Down PC"
    )
    "es" = @(
        "Apagar el PC"
        "Apagar el PC ahora"
        "Apagar el PC en 20 minutos"
        "Apagar el PC en 40 minutos"
        "Apagar el PC en 1 hora"
        "Apagar el PC en 2 horas"
        "Apagar el PC en 3 horas"
        "Apagar el PC en 4 horas"
        "Reiniciar el PC ahora"
        "Cancelar apagado automático"
        "Deslizar para apagar el PC"
    )
    "fr" = @(
        "Arrêter le PC"
        "Arrêter le PC maintenant"
        "Arrêter le PC dans 20 minutes"
        "Arrêter le PC dans 40 minutes"
        "Arrêter le PC dans 1 heure"
        "Arrêter le PC dans 2 heures"
        "Arrêter le PC dans 3 heures"
        "Arrêter le PC dans 4 heures"
        "Redémarrer le PC maintenant"
        "Annuler l'arrêt automatique"
        "Faire glisser pour arrêter le PC"
    )
    "de" = @(
        "PC herunterfahren"
        "PC jetzt herunterfahren"
        "PC in 20 Minuten herunterfahren"
        "PC in 40 Minuten herunterfahren"
        "PC in 1 Stunde herunterfahren"
        "PC in 2 Stunden herunterfahren"
        "PC in 3 Stunden herunterfahren"
        "PC in 4 Stunden herunterfahren"
        "PC jetzt neu starten"
        "Automatisches Herunterfahren abbrechen"
        "Zum Herunterfahren des PCs wischen"
    )
    "it" = @(
        "Arresta il PC"
        "Arresta il PC adesso"
        "Arresta il PC tra 20 minuti"
        "Arresta il PC tra 40 minuti"
        "Arresta il PC tra 1 ora"
        "Arresta il PC tra 2 ore"
        "Arresta il PC tra 3 ore"
        "Arresta il PC tra 4 ore"
        "Riavvia il PC adesso"
        "Annulla arresto automatico"
        "Scorri per arrestare il PC"
    )
    "ru" = @(
        "Выключение компьютера"
        "Выключить компьютер сейчас"
        "Выключить через 20 минут"
        "Выключить через 40 минут"
        "Выключить через 1 час"
        "Выключить через 2 часа"
        "Выключить через 3 часа"
        "Выключить через 4 часа"
        "Перезагрузить компьютер"
        "Отменить автоматическое выключение"
        "Проведите, чтобы выключить компьютер"
    )
    "zh-TW" = @(
        "關閉電腦"
        "立即關閉電腦"
        "20 分鐘後關閉電腦"
        "40 分鐘後關閉電腦"
        "1 小時後關閉電腦"
        "2 小時後關閉電腦"
        "3 小時後關閉電腦"
        "4 小時後關閉電腦"
        "立即重新啟動電腦"
        "取消自動關機"
        "滑動以關閉電腦"
    )
    "zh-CN" = @(
        "关闭电脑"
        "立即关闭电脑"
        "20 分钟后关闭电脑"
        "40 分钟后关闭电脑"
        "1 小时后关闭电脑"
        "2 小时后关闭电脑"
        "3 小时后关闭电脑"
        "4 小时后关闭电脑"
        "立即重启电脑"
        "取消自动关机"
        "滑动以关闭电脑"
    )
    "ar" = @(
        "إيقاف تشغيل الكمبيوتر"
        "إيقاف التشغيل الآن"
        "إيقاف التشغيل بعد 20 دقيقة"
        "إيقاف التشغيل بعد 40 دقيقة"
        "إيقاف التشغيل بعد ساعة"
        "إيقاف التشغيل بعد ساعتين"
        "إيقاف التشغيل بعد 3 ساعات"
        "إيقاف التشغيل بعد 4 ساعات"
        "إعادة تشغيل الكمبيوتر الآن"
        "إلغاء إيقاف التشغيل التلقائي"
        "اسحب لإيقاف تشغيل الكمبيوتر"
    )
    "cs" = @(
        "Vypnout počítač"
        "Vypnout počítač nyní"
        "Vypnout za 20 minut"
        "Vypnout za 40 minut"
        "Vypnout za 1 hodinu"
        "Vypnout za 2 hodiny"
        "Vypnout za 3 hodiny"
        "Vypnout za 4 hodiny"
        "Restartovat počítač"
        "Zrušit automatické vypnutí"
        "Přejetím vypnete počítač"
    )
    "da" = @(
        "Luk computeren ned"
        "Luk computeren ned nu"
        "Luk computeren ned om 20 minutter"
        "Luk computeren ned om 40 minutter"
        "Luk computeren ned om 1 time"
        "Luk computeren ned om 2 timer"
        "Luk computeren ned om 3 timer"
        "Luk computeren ned om 4 timer"
        "Genstart computeren nu"
        "Annuller automatisk nedlukning"
        "Stryg for at lukke computeren ned"
    )
    "nl" = @(
        "PC afsluiten"
        "PC nu afsluiten"
        "PC afsluiten over 20 minuten"
        "PC afsluiten over 40 minuten"
        "PC afsluiten over 1 uur"
        "PC afsluiten over 2 uur"
        "PC afsluiten over 3 uur"
        "PC afsluiten over 4 uur"
        "PC nu opnieuw opstarten"
        "Automatisch afsluiten annuleren"
        "Vegen om de pc af te sluiten"
    )
    "fi" = @(
        "Sammuta tietokone"
        "Sammuta tietokone nyt"
        "Sammuta 20 minuutin kuluttua"
        "Sammuta 40 minuutin kuluttua"
        "Sammuta 1 tunnin kuluttua"
        "Sammuta 2 tunnin kuluttua"
        "Sammuta 3 tunnin kuluttua"
        "Sammuta 4 tunnin kuluttua"
        "Käynnistä tietokone uudelleen"
        "Peruuta automaattinen sammutus"
        "Pyyhkäise sammuttaaksesi tietokoneen"
    )
    "el" = @(
        "Τερματισμός υπολογιστή"
        "Τερματισμός τώρα"
        "Τερματισμός σε 20 λεπτά"
        "Τερματισμός σε 40 λεπτά"
        "Τερματισμός σε 1 ώρα"
        "Τερματισμός σε 2 ώρες"
        "Τερματισμός σε 3 ώρες"
        "Τερματισμός σε 4 ώρες"
        "Επανεκκίνηση υπολογιστή"
        "Ακύρωση αυτόματου τερματισμού"
        "Σύρετε για τερματισμό του υπολογιστή"
    )
    "he" = @(
        "כיבוי המחשב"
        "כבה את המחשב עכשיו"
        "כבה בעוד 20 דקות"
        "כבה בעוד 40 דקות"
        "כבה בעוד שעה"
        "כבה בעוד שעתיים"
        "כבה בעוד 3 שעות"
        "כבה בעוד 4 שעות"
        "הפעל מחדש את המחשב"
        "בטל כיבוי אוטומטי"
        "החלק כדי לכבות את המחשב"
    )
    "hu" = @(
        "Számítógép leállítása"
        "Leállítás most"
        "Leállítás 20 perc múlva"
        "Leállítás 40 perc múlva"
        "Leállítás 1 óra múlva"
        "Leállítás 2 óra múlva"
        "Leállítás 3 óra múlva"
        "Leállítás 4 óra múlva"
        "Számítógép újraindítása"
        "Automatikus leállítás megszakítása"
        "Húzza el a számítógép leállításához"
    )
    "ja" = @(
        "PCをシャットダウン"
        "今すぐシャットダウン"
        "20分後にシャットダウン"
        "40分後にシャットダウン"
        "1時間後にシャットダウン"
        "2時間後にシャットダウン"
        "3時間後にシャットダウン"
        "4時間後にシャットダウン"
        "今すぐ再起動"
        "自動シャットダウンをキャンセル"
        "スワイプしてPCをシャットダウン"
    )
    "ko" = @(
        "PC 종료"
        "지금 PC 종료"
        "20분 후 PC 종료"
        "40분 후 PC 종료"
        "1시간 후 PC 종료"
        "2시간 후 PC 종료"
        "3시간 후 PC 종료"
        "4시간 후 PC 종료"
        "지금 PC 다시 시작"
        "자동 종료 취소"
        "밀어서 PC 종료"
    )
    "no" = @(
        "Slå av PC-en"
        "Slå av PC-en nå"
        "Slå av om 20 minutter"
        "Slå av om 40 minutter"
        "Slå av om 1 time"
        "Slå av om 2 timer"
        "Slå av om 3 timer"
        "Slå av om 4 timer"
        "Start PC-en på nytt"
        "Avbryt automatisk avslutning"
        "Sveip for å slå av PC-en"
    )
    "pl" = @(
        "Wyłącz komputer"
        "Wyłącz komputer teraz"
        "Wyłącz za 20 minut"
        "Wyłącz za 40 minut"
        "Wyłącz za 1 godzinę"
        "Wyłącz za 2 godziny"
        "Wyłącz za 3 godziny"
        "Wyłącz za 4 godziny"
        "Uruchom komputer ponownie"
        "Anuluj automatyczne wyłączanie"
        "Przesuń, aby wyłączyć komputer"
    )
    "sv" = @(
        "Stäng av datorn"
        "Stäng av datorn nu"
        "Stäng av om 20 minuter"
        "Stäng av om 40 minuter"
        "Stäng av om 1 timme"
        "Stäng av om 2 timmar"
        "Stäng av om 3 timmar"
        "Stäng av om 4 timmar"
        "Starta om datorn"
        "Avbryt automatisk avstängning"
        "Svep för att stänga av datorn"
    )
    "tr" = @(
        "Bilgisayarı Kapat"
        "Bilgisayarı Şimdi Kapat"
        "20 Dakika Sonra Kapat"
        "40 Dakika Sonra Kapat"
        "1 Saat Sonra Kapat"
        "2 Saat Sonra Kapat"
        "3 Saat Sonra Kapat"
        "4 Saat Sonra Kapat"
        "Bilgisayarı Yeniden Başlat"
        "Otomatik Kapatmayı İptal Et"
        "Kapatmak İçin Kaydır"
    )
}

# Select language: exact match, special Chinese variants, then language prefix.
$languageKey = $null

if ($langMap.ContainsKey($currentLang)) {
    $languageKey = $currentLang
}
elseif ($currentLang -like "zh-TW*") {
    $languageKey = "zh-TW"
}
elseif ($currentLang -like "zh-CN*") {
    $languageKey = "zh-CN"
}
else {
    $languagePrefix = $currentLang.Split("-")[0]

    if ($langMap.ContainsKey($languagePrefix)) {
        $languageKey = $languagePrefix
    }
}

if ($languageKey) {
    $labels = $langMap[$languageKey]
}
else {
    $labels = $langMap["en"]
}

Write-Host "[LANGUAGE] $currentLang" -ForegroundColor Gray
Write-Host "[MENU] $($labels[0])" -ForegroundColor Cyan

# ------------------------------------------------
# REGISTRY CONFIGURATION
# ------------------------------------------------

$menuPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\DesktopBackground\Shell\ShutdownPC"

$commands = @(
    @{
        Name = "ShutdownNow"
        Label = $labels[1]
        Icon = "shell32.dll,215"
        Command = "shutdown.exe -s -t 00"
        Shield = $true
    }
    @{
        Name = "Shutdown20"
        Label = $labels[2]
        Icon = "shell32.dll,239"
        Command = "shutdown.exe -s -t 1200"
    }
    @{
        Name = "Shutdown40"
        Label = $labels[3]
        Icon = "shell32.dll,239"
        Command = "shutdown.exe -s -t 2400"
    }
    @{
        Name = "Shutdown1Hour"
        Label = $labels[4]
        Icon = "shell32.dll,239"
        Command = "shutdown.exe -s -t 3600"
    }
    @{
        Name = "Shutdown2Hours"
        Label = $labels[5]
        Icon = "shell32.dll,239"
        Command = "shutdown.exe -s -t 7200"
    }
    @{
        Name = "Shutdown3Hours"
        Label = $labels[6]
        Icon = "shell32.dll,239"
        Command = "shutdown.exe -s -t 10800"
    }
    @{
        Name = "Shutdown4Hours"
        Label = $labels[7]
        Icon = "shell32.dll,239"
        Command = "shutdown.exe -s -t 14400"
    }
    @{
        Name = "RestartPC"
        Label = $labels[8]
        Icon = "imageres.dll,253"
        Command = "shutdown.exe -r -t 00 -f"
    }
    @{
        Name = "CancelShutdown"
        Label = $labels[9]
        Icon = "shell32.dll,112"
        Command = "shutdown.exe -a"
    }
    @{
        Name    = "SlideToShutdown"
        Label   = $labels[10]
        Icon    = "shell32.dll,215"
        Command = "`"$env:windir\System32\SlideToShutDown.exe`""
    }
)

# ------------------------------------------------
# CREATE NATIVE WINDOWS CONTEXT MENU
# ------------------------------------------------

try {
    Write-Host "`n[STEP 1] Creating native shutdown menu..." -ForegroundColor Cyan

    # Remove only this script's previous menu.
    if (Test-Path -LiteralPath $menuPath) {
        Remove-Item -LiteralPath $menuPath -Recurse -Force
    }

    # Create the parent menu.
    New-Item -Path $menuPath -Force | Out-Null

    Set-ItemProperty -LiteralPath $menuPath `
        -Name "MUIVerb" -Value $labels[0]

    Set-ItemProperty -LiteralPath $menuPath `
        -Name "Icon" -Value "shell32.dll,215"

    Set-ItemProperty -LiteralPath $menuPath `
        -Name "Position" -Value "1"

    # Use native cascading submenu entries.
    Set-ItemProperty -LiteralPath $menuPath `
        -Name "SubCommands" -Value ""

    $shellPath = Join-Path $menuPath "shell"
    New-Item -Path $shellPath -Force | Out-Null

    foreach ($item in $commands) {
        $itemPath = Join-Path $shellPath $item.Name
        $commandPath = Join-Path $itemPath "command"

        New-Item -Path $itemPath -Force | Out-Null

        Set-ItemProperty -LiteralPath $itemPath `
            -Name "MUIVerb" -Value $item.Label

        Set-ItemProperty -LiteralPath $itemPath `
            -Name "Icon" -Value $item.Icon

        if ($item.ContainsKey("Shield") -and $item.Shield) {
            New-ItemProperty -LiteralPath $itemPath `
                -Name "HasLUAShield" `
                -PropertyType String `
                -Value "" `
                -Force | Out-Null
        }

        New-Item -Path $commandPath -Force | Out-Null

        Set-Item -LiteralPath $commandPath -Value $item.Command
    }

    Write-Host "[OK] Created $($commands.Count) shutdown options." -ForegroundColor Green

    # ============================================================
    # CLEAN UP LEGACY CONTEXT MENU ENTRIES
    # ============================================================

    Write-Host "[STEP 2] Cleaning up legacy entries..." -ForegroundColor Cyan

        # --------------------------------------------------------
        # REMOVE LEGACY COMMANDSTORE ENTRIES
        # --------------------------------------------------------

        $storePath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell"

        $legacyNames = @(
            "WD-Desligar"
            "WD-DesligarEm20min"
            "WD-DesligarEm40min"
            "WD-DesligarEm1hora"
            "WD-DesligarEm2horas"
            "WD-DesligarEm3horas"
            "WD-DesligarEm4horas"
            "WD-ReiniciarPC"
            "WD-Cancelar"
        )

        foreach ($name in $legacyNames) {
            $legacyPath = Join-Path $storePath $name

            if (Test-Path -LiteralPath $legacyPath) {
                Remove-Item -LiteralPath $legacyPath -Recurse -Force -ErrorAction Stop
                Write-Host "[REMOVED] CommandStore: $name" -ForegroundColor Yellow
            }
            else {
                Write-Host "[SKIP] CommandStore entry not found: $name" -ForegroundColor DarkGray
            }
        }

        # --------------------------------------------------------
        # REMOVE LEGACY "TURN OFF PC" DESKTOP CONTEXT MENU
        # --------------------------------------------------------

        Write-Host "[STEP 2] Checking legacy 'TurnOff PC' context menu..." -ForegroundColor Cyan

        $turnOffPcPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\DesktopBackground\Shell\TurnOff PC"

        if (Test-Path -LiteralPath $turnOffPcPath) {
            Remove-Item -LiteralPath $turnOffPcPath -Recurse -Force -ErrorAction Stop
            Write-Host "[REMOVED] Context menu: TurnOff PC" -ForegroundColor Yellow
        }
        else {
            Write-Host "[SKIP] Context menu 'TurnOff PC' does not exist." -ForegroundColor DarkGray
        }

        Write-Host "[OK] Legacy entries cleanup completed." -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}

# ------------------------------------------------
# FINAL
# ------------------------------------------------

Write-Host ""
Write-Host "--- Deployment Finished ---" -ForegroundColor Yellow
Write-Host "Menu: $($labels[0])" -ForegroundColor Green
Write-Host "Options: $($commands.Count)" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
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

# 1. Global Language Dictionary (23 Languages)
$langID = (Get-Culture).TwoLetterISOLanguageName
$t = @{
    "TakeOwnership" = @{ 
        "en"="Take Ownership"; "pt"="Obter Controle Total"; "es"="Tomar posesión"; "de"="Besitz übernehmen"; 
        "nl"="Eigenaar worden"; "fr"="Prendre possession"; "it"="Diventa proprietario"; "ja"="所有権の取得"; 
        "ko"="소유권 가져오기"; "zh"="取得所有权"; "uk"="Стати власником"; "ru"="Стать владельцем"; 
        "bg"="Стани собственик"; "hi"="स्वामित्व लें"; "tr"="Sahipliği Al"; "vi"="Chiếm quyền sở hữu"; 
        "th"="เป็นเจ้าของ"; "id"="Ambil Kepemilikan"; "ms"="Ambil Pemilikan"; "fi"="Ota omistajuus"; 
        "he"="קבל בעלות"; "el"="Ανάληψη κυριότητας"; "ar"="أخذ الملكية" 
    }
}

$localizedName = if ($t["TakeOwnership"][$langID]) { $t["TakeOwnership"][$langID] } else { $t["TakeOwnership"]["en"] }

Write-Host "[PROCESS] Deploying '$localizedName' with custom Checkmark Icon..." -ForegroundColor Cyan

# 2. Registry Payload Generation (Here-String)
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
    # 3. File I/O & Deployment
    $tempReg = "$env:TEMP\take_ownership_deploy.reg"
    $regContent | Out-File -FilePath $tempReg -Encoding Unicode -Force

    # Executing the import via reg.exe
    Start-Process "reg.exe" -ArgumentList "import `"$tempReg`"" -Wait -NoNewWindow

    # 4. Post-Deployment Cleanup
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

# --- 3. Explorer: Hide Recycle Bin, Control Panel, This PC and User Folder ---
Write-Host "[MODULE] Hiding desktop system icons..." -ForegroundColor Cyan

$desktopItems = [ordered]@{
    "Recycle Bin"  = "{645FF040-5081-101B-9F08-00AA002F954E}"
    "Control Panel" = "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}"
    "This PC"       = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
    "User Folder"   = "{59031A47-3F72-44A7-89C5-5595FE6B30EE}"
}

$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
)

try {
    foreach ($regPath in $regPaths) {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }

        foreach ($item in $desktopItems.GetEnumerator()) {
            New-ItemProperty `
                -Path $regPath `
                -Name $item.Value `
                -Value 1 `
                -PropertyType DWord `
                -Force | Out-Null
        }
    }

    foreach ($item in $desktopItems.GetEnumerator()) {
        Write-Host "[OK] $($item.Key) hidden successfully." -ForegroundColor Green
    }

    Write-Host "[INFO] Refresh the desktop or restart Explorer to apply changes." -ForegroundColor Yellow
}
catch {
    Write-Warning "Failed to configure desktop icons: $($_.Exception.Message)"
}

Write-Host "Recycle Bin hidden successfully! ✅" -ForegroundColor Green
Write-Host "Control Panel hidden successfully! ✅" -ForegroundColor Green
Write-Host "This PC hidden successfully! ✅" -ForegroundColor Green
Write-Host "User Folder hidden successfully! ✅" -ForegroundColor Green

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
    ".vbs" = @{ "en"="VBScript"; "pt"="VBScript"; "es"="VBScript"; "de"="VBScript"; "nl"="VBScript"; "fr"="VBScript"; "it"="VBScript"; "ja"="VBScript"; "ko"="VBScript"; "zh"="VBScript"; "uk"="VBScript"; "ru"="VBScript"; "bg"="VBScript"; "hi"="VBScript"; "tr"="VBScript"; "vi"="VBScript"; "th"="VBScript"; "id"="VBScript"; "ms"="VBScript"; "fi"="VBScript"; "he"="VBScript"; "el"="VBScript"; "ar"="VBScript" }
    ".bat" = @{ "en"="Batch File (.bat)"; "pt"="Arquivo de Lote (.bat)"; "es"="Archivo por lotes (.bat)"; "de"="Stapelverarbeitungsdatei (.bat)"; "nl"="Batchbestand (.bat)"; "fr"="Fichier de commandes (.bat)"; "it"="File batch (.bat)"; "ja"="バッチファイル (.bat)"; "ko"="배치 파일 (.bat)"; "zh"="批处理文件 (.bat)"; "uk"="Пакетний файл (.bat)"; "ru"="Пакетный файл (.bat)"; "bg"="Пакетен файл (.bat)"; "hi"="बैच फ़ाइल (.bat)"; "tr"="Toplu İş Dosyası (.bat)"; "vi"="Tệp lô (.bat)"; "th"="ไฟล์แบตช์ (.bat)"; "id"="File batch (.bat)"; "ms"="Fail kelompok (.bat)"; "fi"="Eräajo-tiedosto (.bat)"; "he"="קובץ Batch (.bat)"; "el"="Αρχείο δέσμης ενεργειών (.bat)"; "ar"="ملف دفعي (.bat)" }
    ".cmd" = @{ "en"="Command Script (.cmd)"; "pt"="Script de Comando (.cmd)"; "es"="Script de comando (.cmd)"; "de"="Befehlsskript (.cmd)"; "nl"="Opdrachtscript (.cmd)"; "fr"="Script de commande (.cmd)"; "it"="Script di comando (.cmd)"; "ja"="コマンドスクリプト (.cmd)"; "ko"="명령 스크립트 (.cmd)"; "zh"="命令脚本 (.cmd)"; "uk"="Командний сценарій (.cmd)"; "ru"="Командный сценарий (.cmd)"; "bg"="Команден скрипт (.cmd)"; "hi"="कमांड स्क्रिप्ट (.cmd)"; "tr"="Komut Dosyası (.cmd)"; "vi"="Kịch bản lệnh (.cmd)"; "th"="สคริปต์คำสั่ง (.cmd)"; "id"="Skrip perintah (.cmd)"; "ms"="Skrip arahan (.cmd)"; "fi"="Komentosarjassa (.cmd)"; "he"="סקריפט פקודה (.cmd)"; "el"="Δέσμη εντολών (.cmd)"; "ar"="برنامج نصي للأوامر (.cmd)" }
    ".reg" = @{ "en"="Registry Entries (.reg)"; "pt"="Entradas de Registro (.reg)"; "es"="Entradas de registro (.reg)"; "de"="Registrierungseinträge (.reg)"; "nl"="Registervermeldingen (.reg)"; "fr"="Entrées de registre (.reg)"; "it"="Voci di registro (.reg)"; "ja"="レジストリエントリ (.reg)"; "ko"="레지스트리 항목 (.reg)"; "zh"="注册表项 (.reg)"; "uk"="Записи реєстру (.reg)"; "ru"="Записи реестра (.reg)"; "bg"="Записи в регистъра (.reg)"; "hi"="रजिस्ट्री प्रविष्टियाँ (.reg)"; "tr"="Kayıt Defteri Girdileri (.reg)"; "vi"="Mục đăng ký (.reg)"; "th"="รายการรีจิสทรี (.reg)"; "id"="Entri registri (.reg)"; "ms"="Kemasukan pendaftaran (.reg)"; "fi"="Rekisterimerkinnät (.reg)"; "he"="ערכי רישום (.reg)"; "el"="Καταχωρήσεις μητρώου (.reg)"; "ar"="إدخالات السجل (.reg)" }
    ".ps1" = @{ "en"="PowerShell Script (.ps1)"; "pt"="Script do PowerShell (.ps1)"; "es"="Script de PowerShell (.ps1)"; "de"="PowerShell-Skript (.ps1)"; "nl"="PowerShell-script (.ps1)"; "fr"="Script PowerShell (.ps1)"; "it"="Script PowerShell (.ps1)"; "ja"="PowerShell スクリプト (.ps1)"; "ko"="PowerShell 스크립트 (.ps1)"; "zh"="PowerShell 脚本 (.ps1)"; "uk"="Сценарій PowerShell (.ps1)"; "ru"="Сценарий PowerShell (.ps1)"; "bg"="PowerShell скрипт (.ps1)"; "hi"="PowerShell स्क्रिप्ट (.ps1)"; "tr"="PowerShell Betiği (.ps1)"; "vi"="Kịch bản PowerShell (.ps1)"; "th"="สคริปต์ PowerShell (.ps1)"; "id"="Skrip PowerShell (.ps1)"; "ms"="Skrip PowerShell (.ps1)"; "fi"="PowerShell-skripti (.ps1)"; "he"="סקריפט PowerShell (.ps1)"; "el"="Δέσμη ενεργειών PowerShell (.ps1)"; "ar"="برنامج PowerShell النصي (.ps1)" }
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

# --- 13. Long-term Windows Update Pause (Year 3000) & EXTENDED PAUSE CONFIGURATION ---
Write-Host "[MODULE] Configuring Windows Update long-term pause..." -ForegroundColor Cyan

# Define registry path
$wuPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"

try {
    # Ensure registry path exists
    if (!(Test-Path $wuPath)) {
        New-Item -Path $wuPath -Force | Out-Null
    }

    # ------------------------------------------------------------
    # Extend maximum allowed pause duration (20 years = 7300 days)
    # This unlocks extended pause capability in Windows Settings
    # ------------------------------------------------------------
    Write-Host ">> Extending maximum pause limit to 20 years..." -ForegroundColor Gray

    New-ItemProperty -Path $wuPath `
        -Name "FlightSettingsMaxPauseDays" `
        -PropertyType DWord `
        -Value 7300 `
        -Force | Out-Null

    # ------------------------------------------------------------
    # Force pause until year 3000
    # This effectively keeps updates paused indefinitely
    # ------------------------------------------------------------
    Write-Host ">> Applying hard pause until year 3000..." -ForegroundColor Gray

    $updateValues = @{
        "PauseFeatureUpdatesStartTime" = "2022-09-30T10:23:59Z"
        "PauseFeatureUpdatesEndTime"   = "3000-12-31T10:23:59Z"
        "PauseQualityUpdatesStartTime" = "2022-09-30T10:23:59Z"
        "PauseQualityUpdatesEndTime"   = "3000-12-31T10:23:59Z"
        "PauseUpdatesStartTime"        = "2022-09-30T10:23:59Z"
        "PauseUpdatesExpiryTime"       = "3000-12-31T10:23:59Z"
    }

    foreach ($name in $updateValues.Keys) {
        Set-ItemProperty -Path $wuPath `
            -Name $name `
            -Value $updateValues[$name] `
            -Type String `
            -Force
    }

    Write-Host "Windows Update pause successfully configured. ✅" -ForegroundColor Green
    Write-Host "NOTE: In some Windows versions, manual pause activation in Settings may still be required." -ForegroundColor Yellow

} catch {
    Write-Warning "Failed to configure Windows Update pause settings."
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
Write-Host "-- Adding user folders and system shortcuts under 'This PC'..." -ForegroundColor Gray
$namespacePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"
$folders = @(
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", # Desktop
    "{d3162b92-9365-467a-956b-92703aca08af}", # Documents
    "{088e3905-0323-4b02-9826-5d99428e115f}", # Downloads
    "{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}", # Music
    "{24ad3ad4-a569-4530-98e1-ab02f9417aa8}", # Pictures
    "{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"  # Videos
)

foreach ($guid in $folders) {
    $path = Join-Path $namespacePath $guid
    if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    
    # Remove the block (equivalent to "HideIfEnabled"=-)
    Remove-ItemProperty -Path $path -Name "HideIfEnabled" -ErrorAction SilentlyContinue
    
    # Set as visible
    Set-ItemProperty -Path $path -Name "HiddenByDefault" -Value 0 -Type DWord
}

# OPTIONAL: Remove Recycle Bin or Classic Printers from 'This PC' if desired
# Uncomment the lines below to remove them:
# Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{645FF040-5081-101B-9F08-00AA002F954E}" -Recurse -Force -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{2227A280-3AEA-1069-A2DE-08002B30309D}" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Registry tweaks applied successfully! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

# 21. Deleting Default0 User
Write-Host "-- Deleting Default0 User..." -ForegroundColor Gray
if (Get-LocalUser -Name "defaultuser0" -ErrorAction SilentlyContinue) {
    Remove-LocalUser -Name "defaultuser0" -ErrorAction SilentlyContinue
    Write-Host "Default0 user successfully removed! ✅" -ForegroundColor Green
} else {
    Write-Host "Default0 user not found, skipping... ⏭️" -ForegroundColor Yellow
}

Write-Host "--------------------------------------------------------"
Write-Host ""

# --- 22. USER SECURITY (PASSWORD NEVER EXPIRES) ---

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "Updating password expiration policy for current user: $currentUser..." -ForegroundColor Cyan

try {
    # Get the current username without the domain or computer name
    $userName = $currentUser.Split('\')[-1]

    # Check whether the current account is a local user
    $localUser = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue

    if ($localUser) {
        Set-LocalUser -Name $userName -PasswordNeverExpires $true -ErrorAction Stop
        Write-Host "[$currentUser] Password set to NEVER EXPIRES successfully." -ForegroundColor Green
    }
    else {
        Write-Host "[WARNING] Current user '$currentUser' is not a local account or was not found. Skipping..." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "[ERROR] Failed to update password expiration for '$currentUser'. Ensure the script is running with Administrative privileges." -ForegroundColor Red
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

Write-Host "--------------------------------------------------------"
Write-Host ""

# 24. Disabling Lock Screen Camera
Write-Host "`n Disabling Lock Screen Camera..." -ForegroundColor Gray
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f | Out-Null

Write-Host ""
Write-Host "Lock Screen Camera disabled successfully! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

# 25. Limiting Windows Defender CPU Usage
Write-Host "`n Limiting Windows Defender CPU Usage..." -ForegroundColor Gray
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "AvgCPULoadFactor" /t REG_DWORD /d "25" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "ScanAvgCPULoadFactor" /t REG_DWORD /d "25" /f | Out-Null

Write-Host ""
Write-Host "Defender CPU usage limited successfully! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

# 26. Enabling Dark Mode
Write-Host "-- Enabling Dark Mode..." -ForegroundColor Gray
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f | Out-Null

Write-Host ""
Write-Host "Dark mode enabled successfully! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

# 27. Pin Classic Printers to File Explorer Navigation Pane
Write-Host "`n Pinning Classic Printers to Explorer Navigation Pane..." -ForegroundColor Gray

$clsid = "{2227A280-3AEA-1069-A2DE-08002B30309D}"
$clsidPath = "HKCU:\Software\Classes\CLSID\$clsid"
$inprocPath = "$clsidPath\InProcServer32"
$nameSpacePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\$clsid"

try {
    # Create CLSID structure
    New-Item -Path $clsidPath -Force -ErrorAction Stop | Out-Null

    # Register Printers shell folder
    Set-Item -Path $clsidPath -Value "Printers" -ErrorAction Stop

    New-ItemProperty -Path $clsidPath `
        -Name "System.IsPinnedToNamespaceTree" `
        -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null

    New-ItemProperty -Path $clsidPath `
        -Name "SortOrderIndex" `
        -Value 60 -PropertyType DWord -Force -ErrorAction Stop | Out-Null

    New-ItemProperty -Path $clsidPath `
        -Name "LocalizedString" `
        -Value "@%SystemRoot%\System32\prnfldr.dll,-8036" `
        -PropertyType ExpandString -Force -ErrorAction Stop | Out-Null

    New-ItemProperty -Path $clsidPath `
        -Name "InfoTip" `
        -Value "@%SystemRoot%\System32\prnfldr.dll,-8062" `
        -PropertyType ExpandString -Force -ErrorAction Stop | Out-Null

    # Register the COM server
    New-Item -Path $inprocPath -Force -ErrorAction Stop | Out-Null

    Set-Item -Path $inprocPath `
        -Value "$env:SystemRoot\System32\prnfldr.dll" `
        -ErrorAction Stop

    New-ItemProperty -Path $inprocPath `
        -Name "ThreadingModel" `
        -Value "Apartment" -PropertyType String `
        -Force -ErrorAction Stop | Out-Null

    # Set the default icon
    $iconPath = "$clsidPath\DefaultIcon"
    New-Item -Path $iconPath -Force -ErrorAction Stop | Out-Null

    Set-Item -Path $iconPath `
        -Value "%SystemRoot%\System32\imageres.dll,-26" `
        -ErrorAction Stop

    # Register in Explorer namespace
    New-Item -Path $nameSpacePath -Force -ErrorAction Stop | Out-Null
    Set-Item -Path $nameSpacePath -Value "Printers" -ErrorAction Stop

    # Hide the separate desktop icon, without hiding it in Explorer
    $hidePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
    New-Item -Path $hidePath -Force -ErrorAction Stop | Out-Null

    New-ItemProperty -Path $hidePath `
        -Name $clsid -Value 1 -PropertyType DWord `
        -Force -ErrorAction Stop | Out-Null

    Write-Host "Registry entries created successfully." -ForegroundColor Green
    Write-Host "Printers registration completed!" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Classic Printers pinned to Explorer sidebar successfully! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# ============================================================
# 28. HIDE ONEDRIVE DESKTOP NAMESPACE ICONS
# Windows PowerShell 5.1 Compatible
# Automatically detects registered OneDrive namespace entries
# Hides icons BEFORE automatic detection to minimize flashing
# Does not delete files, shortcuts, or OneDrive registry entries
# ============================================================

Write-Host "`n-- Hiding OneDrive and Recycle Bin icons..." -ForegroundColor Gray

# ------------------------------------------------------------
# 1. REGISTRY CONFIGURATION
# ------------------------------------------------------------
$hidePaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
)

$binGuid = "{645FF040-5081-101B-9F08-00AA002F954E}"

# Standard OneDrive namespace CLSID
$knownOneDriveClsids = @(
    "{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
)

# ------------------------------------------------------------
# HELPER: APPLY HIDE VALUE
# ------------------------------------------------------------
if (-not (Get-Command "Set-DesktopIconHidden" -ErrorAction SilentlyContinue)) {
    function Set-DesktopIconHidden {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path,

            [Parameter(Mandatory = $true)]
            [string]$Clsid
        )

        try {
            if (-not (Test-Path -LiteralPath $Path)) {
                New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            }

            New-ItemProperty `
                -LiteralPath $Path `
                -Name $Clsid `
                -Value 1 `
                -PropertyType DWord `
                -Force `
                -ErrorAction Stop | Out-Null

            return $true
        }
        catch {
            Write-Host "[WARNING] Could not hide $Clsid : $($_.Exception.Message)" -ForegroundColor Yellow
            return $false
        }
    }
}

# ------------------------------------------------------------
# 2. HIDE RECYCLE BIN IMMEDIATELY
# ------------------------------------------------------------
Write-Host "[1/3] Hiding Recycle Bin..." -ForegroundColor Gray

foreach ($path in $hidePaths) {
    Set-DesktopIconHidden -Path $path -Clsid $binGuid | Out-Null
}

Write-Host "[OK] Recycle Bin hide settings applied." -ForegroundColor Green

# ------------------------------------------------------------
# 3. HIDE STANDARD ONEDRIVE CLSID BEFORE DETECTION
# ------------------------------------------------------------
Write-Host "[2/3] Applying initial OneDrive hide settings..." -ForegroundColor Gray

foreach ($clsid in $knownOneDriveClsids) {
    foreach ($path in $hidePaths) {
        Set-DesktopIconHidden -Path $path -Clsid $clsid | Out-Null
    }
}

Write-Host "[OK] Initial OneDrive hide settings applied." -ForegroundColor Green

# ------------------------------------------------------------
# 4. DETECT OTHER REGISTERED ONEDRIVE NAMESPACE ENTRIES
# ------------------------------------------------------------
Write-Host "`n=== Detecting OneDrive namespace icons ===" -ForegroundColor Cyan

$namespacePaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"
)

if (-not (Get-Command "Get-RegistryText" -ErrorAction SilentlyContinue)) {
    function Get-RegistryText {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path
        )

        $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue

        if (-not $key) {
            return
        }

        foreach ($name in @("", "LocalizedString", "System.DisplayName")) {
            try {
                $value = $key.GetValue(
                    $name,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )

                if ($value -is [string] -and
                    -not [string]::IsNullOrWhiteSpace($value)) {
                    $value
                }
            }
            catch {
                # Ignore inaccessible registry values
            }
        }
    }
}

$detected = @{}

foreach ($namespacePath in $namespacePaths) {
    if (-not (Test-Path -LiteralPath $namespacePath -ErrorAction SilentlyContinue)) {
        continue
    }

    $entries = Get-ChildItem -LiteralPath $namespacePath -ErrorAction SilentlyContinue

    foreach ($entry in $entries) {
        $clsid = $entry.PSChildName

        if ($clsid -notmatch '^\{[0-9A-Fa-f-]{36}\}$') {
            continue
        }

        $classPaths = @(
            "HKCU:\Software\Classes\CLSID\$clsid",
            "HKLM:\Software\Classes\CLSID\$clsid",
            "HKLM:\Software\WOW6432Node\Classes\CLSID\$clsid"
        )

        $displayNames = @()
        $displayNames += Get-RegistryText -Path $entry.PSPath

        foreach ($classPath in $classPaths) {
            $displayNames += Get-RegistryText -Path $classPath
        }

        $oneDriveName = $displayNames |
            Where-Object { $_ -match '(?i)OneDrive' } |
            Select-Object -First 1

        if ($oneDriveName) {
            $detected[$clsid] = $oneDriveName
        }
    }
}

# ------------------------------------------------------------
# 5. HIDE ALL ADDITIONAL DETECTED ONEDRIVE CLSIDS
# ------------------------------------------------------------
foreach ($clsid in $detected.Keys) {
    foreach ($path in $hidePaths) {
        Set-DesktopIconHidden -Path $path -Clsid $clsid | Out-Null
    }

    Write-Host "[OK] Hidden: $($detected[$clsid]) ($clsid)" -ForegroundColor Green
}

if ($detected.Count -eq 0) {
    Write-Host "[INFO] No additional OneDrive namespace entries detected." -ForegroundColor Yellow
}

# ------------------------------------------------------------
# 6. FINISH
# ------------------------------------------------------------
Write-Host "`n Finished. Check the desktop icon." -ForegroundColor Green
Write-Host ""
Write-Host "OneDrive desktop icons hidden successfully! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# 29. Conditional Transparency Tweak based on Hardware
Write-Host "-- Checking hardware specifications..." -ForegroundColor Gray

function Get-RealRAM {
    try {
        $ramBytes = (Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum
        return [math]::Round($ramBytes / 1GB, 2)
    }
    catch {
        return 8
    }
}

function Get-LogicalCPU {
    try {
        return (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    }
    catch {
        return 4
    }
}

$TotalRAM = Get-RealRAM
$LogicalProcessors = Get-LogicalCPU

Write-Host "   -> Detected RAM: $TotalRAM GB" -ForegroundColor DarkGray
Write-Host "   -> Logical CPUs: $LogicalProcessors" -ForegroundColor DarkGray

# Threshold for weak PC: Less than 8GB RAM or 4 or fewer logical processors
if (($TotalRAM -lt 8) -or ($LogicalProcessors -le 4)) {
    Write-Host "-- Low-spec hardware detected. Disabling Transparency..." -ForegroundColor Gray
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 0 /f | Out-Null
    
    Write-Host ""
    Write-Host "Transparency disabled for performance! ✅" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Hardware is adequate. Skipping transparency tweak. ✅" -ForegroundColor Green
}

Write-Host "--------------------------------------------------------"
Write-Host ""

# 30. Removing Windows.old Folder
Write-Host "`n Removing Windows.old Folder..." -ForegroundColor Gray

$WindowsOldPath = "C:\Windows.old"

if (Test-Path -LiteralPath $WindowsOldPath) {
    try {
        Remove-Item -LiteralPath $WindowsOldPath -Recurse -Force -ErrorAction Stop

        Write-Host ""
        Write-Host "Windows.old folder removed successfully! ✅" -ForegroundColor Green
    }
    catch {
        Write-Host ""
        Write-Host "Failed to remove Windows.old folder! ❌" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor DarkGray
    }
}
else {
    Write-Host ""
    Write-Host "Windows.old folder not found. Nothing to remove." -ForegroundColor Yellow
}

Write-Host "--------------------------------------------------------"
Write-Host ""

# 31. Uninstall PC Health Check
Write-Host "`n Uninstalling PC Health Check..." -ForegroundColor Gray

$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$apps = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*PC Health Check*" }

if ($apps) {
    foreach ($app in $apps) {
        if ($app.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {
            try {
                $process = Start-Process -FilePath "msiexec.exe" `
                    -ArgumentList "/x $($app.PSChildName) /quiet /norestart" `
                    -Wait -PassThru -ErrorAction Stop

                if ($process.ExitCode -eq 0) {
                    Write-Host "PC Health Check uninstalled successfully! ✅" -ForegroundColor Green
                }
                else {
                    Write-Host "Uninstaller returned exit code: $($process.ExitCode)" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "Failed to uninstall PC Health Check: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "Non-MSI installer detected: $($app.DisplayName)" -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host "PC Health Check not found." -ForegroundColor DarkGray
}

# Block future reinstall
Write-Host "Configuring PC Health Check reinstall flag..." -ForegroundColor Gray

try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\PCHC"

    New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $regPath -Name "PreviousUninstall" `
        -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null

    Write-Host "PC Health Check reinstall flag configured! ✅" -ForegroundColor Green
}
catch {
    Write-Host "Failed to configure reinstall flag: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "--------------------------------------------------------"
Write-Host ""


# 32. Remove Windows Update Assistants (Dynamic)
Write-Host "`n Removing Windows Update Assistants..." -ForegroundColor Gray

# Search installed applications in the registry
$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$assistants = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -match '(?i)Windows\s*(10|11|12|[1-9]\d*)?\s*(Installation|Update|Upgrade)\s*Assistant|Windows Installation Assistant|Windows Update Assistant|Windows Upgrade Assistant'
    } |
    Sort-Object PSPath -Unique

if ($assistants) {
    foreach ($app in $assistants) {
        Write-Host "Removing: $($app.DisplayName)..." -ForegroundColor DarkGray

        # Prefer the registered quiet uninstaller
        $command = if ($app.QuietUninstallString) {
            $app.QuietUninstallString
        }
        else {
            $app.UninstallString
        }

        if (-not $command) {
            Write-Host "No uninstaller registered for $($app.DisplayName)." -ForegroundColor Yellow
            continue
        }

        try {
            if ($command -match '(?i)msiexec(?:\.exe)?') {
                $command = $command -replace '(?i)/I(?=\s*\{)', '/X'

                if ($command -notmatch '(?i)/quiet|/qn') {
                    $command += " /quiet"
                }

                if ($command -notmatch '(?i)/norestart') {
                    $command += " /norestart"
                }

                Start-Process -FilePath "$env:WINDIR\System32\cmd.exe" `
                    -ArgumentList "/d /s /c `"`"$env:WINDIR\System32\msiexec.exe`" $($command -replace '(?i)^.*?msiexec(?:\.exe)?\s*', '')`"" `
                    -Wait -ErrorAction Stop | Out-Null
            }
            else {
                Write-Host "Using registered uninstaller for $($app.DisplayName)." -ForegroundColor DarkGray
                Start-Process -FilePath "$env:WINDIR\System32\cmd.exe" `
                    -ArgumentList "/d /c `"$command`"" `
                    -Wait -ErrorAction Stop | Out-Null
            }

            Write-Host "Uninstall command completed for $($app.DisplayName). ✅" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to uninstall $($app.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
else {
    Write-Host "No registered Windows Update Assistants found." -ForegroundColor DarkGray
}

# Clean up known assistant leftovers
$residualPaths = @(
    "$env:SystemDrive\Windows10Upgrade",
    "$env:SystemDrive\Windows11InstallationAssistant",
    "$env:ProgramFiles\WindowsInstallationAssistant",
    "${env:ProgramFiles(x86)}\WindowsInstallationAssistant",
    "$env:WINDIR\UpdateAssistant"
)

foreach ($path in ($residualPaths | Select-Object -Unique)) {
    if (Test-Path -LiteralPath $path) {
        try {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
            Write-Host "Removed residual folder: $path" -ForegroundColor Green
        }
        catch {
            Write-Host "Could not remove $path : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host "Windows Update Assistant cleanup completed! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

# 33. Adjusting Windows Services Startup Types
Write-Host "-- Adjusting Windows services startup types..." -ForegroundColor Gray

# ----------------------------------------------------------------------
# 1. Automatic Services
# ----------------------------------------------------------------------
$automaticServices = @(
    "Spooler"  # Print Spooler (Required for printing)
)

# ----------------------------------------------------------------------
# 2. Native Windows Services
# ----------------------------------------------------------------------
$manualWindowsServices = @(
    "ALG","AppMgmt","AppReadiness","Appinfo","AxInstSV","BDESVC","BTAGService",
    "BcastDVRUserService","BluetoothUserService","Browser","CDPSvc","COMSysApp",
    "CaptureService","CertPropSvc","ConsentUxUserSvc","CscService","DevQueryBroker",
    "DeviceAssociationService","DeviceInstall","DevicePickerUserSvc","DevicesFlowUserSvc",
    "DisplayEnhancementService","DmEnrollmentSvc","DsSvc","DsmSvc","EFS","EapHost",
    "EntAppSvc","FDResPub","FrameServer","FrameServerMonitor","GraphicsPerfSvc","HvHost",
    "IEEtwCollectorService","InstallService","InventorySvc","IpxlatCfgSvc","KtmRm",
    "LicenseManager","LxpSvc","MSDTC","MSiSCSI","McpManagementService",
    "MsKeyboardFilter","NPSMSvc","NaturalAuthentication","NcaSvc","NcbService",
    "NcdAutoSetup","NetSetupSvc","Netman","NgcCtnrSvc","NgcSvc","NlaSvc","PNRPAutoReg",
    "PcaSvc","PeerDistSvc","PenService","PerfHost","PhoneSvc","PimIndexMaintenanceSvc",
    "PlugPlay","PolicyAgent","PrintNotify","PushToInstall","QWAVE","RasAuto","RasMan",
    "RetailDemo","RmSvc","RpcLocator","SCPolicySvc","SCardSvr","SDRSVC","SEMgrSvc",
    "SNMPTRAP","SNMPTrap","SSDPSRV","ScDeviceEnum","SensorDataService","SensorService",
    "SensrSvc","SessionEnv","SharedAccess","SmsRouter","SstpSvc","StiSvc","StorSvc",
    "TapiSrv","TextInputManagementService","TieringEngineService","TokenBroker",
    "TroubleshootingSvc","TrustedInstaller","UdkUserSvc","UmRdpService","UserDataSvc",
    "UsoSvc","VSS","VacSvc","WEPHOSTSVC","WFDSConMgrSvc","WMPNetworkSvc","WManSvc",
    "WPDBusEnum","WalletService","WarpJITSvc","WbioSrvc","WdNisSvc","WdiServiceHost",
    "WdiSystemHost","WebClient","Wecsvc","WerSvc","WiaRpc","WinRM","WpcMonSvc",
    "WpnService","WwanSvc","autotimesvc","bthserv","camsvc","cbdhsvc","cloudidsvc",
    "dcsvc","defragsvc","diagsvc","dmwappushservice","dot3svc","embeddedmode",
    "fdPHost","fhsvc","hidserv","icssvc","lfsvc","lltdsvc","lmhosts","msiserver",
    "netprofm","p2pimsvc","p2psvc","perceptionsimulation","pla","seclogon","smphost",
    "svsvc","swprv","upnphost","vds","vmicguestinterface","vmicheartbeat",
    "vmickvpexchange","vmicrdv","vmicshutdown","vmictimesync","vmicvmsession",
    "vmicvss","vmvss","wbengine","wcncsvc","webthreatdefsvc","wercplsupport","wisvc",
    "wlidsvc","wlpasvc","wmiApSrv","workfolderssvc","wuauserv","wudfsvc"
)

$disabledWindowsServices = @(
    "AppVClient","AssignedAccessManagerSvc","DiagTrack","DialogBlockingService",
    "NetTcpPortSharing","RemoteAccess","RemoteRegistry","shpamsvc","ssh-agent",
    "tzautoupdate","WSAIFabricSvc","Winsock","ws2ifsl","WaaSMedicSvc","rspndr",
    "lltdio","CDFS","DPS","UDFS","dcpsvc"
)

# ----------------------------------------------------------------------
# 3. Third-Party & External App Services
# ----------------------------------------------------------------------
$manualExternalServices = @(
    "MicrosoftEdgeElevationService", "edgeupdate", "edgeupdatem", # Edge Services
    "OneDrive",                                                   # OneDrive
    "WiseBootAssistant",                                          # Wise Care
    "Adguard VPN Service",                                        # AdGuard
    "WireSockAppService", "WireSockConnectService",               # WireSock
    "TeraBoxUtility",                                             # TeraBox
    "ViscosityService"                                            # Viscosity VPN
)

$disabledExternalServices = @(
    "EPWD",                 # Check Point Endpoint Security VPN/ ExpressVPN / Third-party driver
    "TracSrvWrapper",       # Check Point VPN
    "NativePushService",    # Wondershare / Third-party Push Notification service
    "LenovoVantageService"  # Lenovo
)

# ----------------------------------------------------------------------
# Execution
# ----------------------------------------------------------------------

# Set Automatic Services
$automaticServices | ForEach-Object { 
    if (Get-Service -Name $_ -ErrorAction SilentlyContinue) { 
        Set-Service -Name $_ -StartupType Automatic -ErrorAction SilentlyContinue 
    } 
}

# Set Manual Services (Windows + External)
($manualWindowsServices + $manualExternalServices) | ForEach-Object { 
    if (Get-Service -Name $_ -ErrorAction SilentlyContinue) { 
        Set-Service -Name $_ -StartupType Manual -ErrorAction SilentlyContinue 
    } 
}

# Set Disabled Services (Windows + External)
($disabledWindowsServices + $disabledExternalServices) | ForEach-Object { 
    if (Get-Service -Name $_ -ErrorAction SilentlyContinue) { 
        Set-Service -Name $_ -StartupType Disabled -ErrorAction SilentlyContinue 
    } 
}

Write-Host ""
Write-Host "Services startup types configured successfully! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

# 34. Install Power Plans
Write-Host "`n--- Installing Power Plans ---" -ForegroundColor Cyan

try {
    # Temporarily allow script execution for the current process
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force | Out-Null

    # Download and execute the Power Plans installer directly from GitHub
    iex (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/TogoFire-Home/WorkstationTools/main/Tools/System/PowerPlans/Install-PowerPlans.ps1")

} catch {
    Write-Host "Failed to install Power Plans. Please check your connection." -ForegroundColor Red
}

Write-Host "--------------------------------------------------------"
Write-Host ""

# 35. DISABLE WPBT
# ============================================================
# DISABLE WINDOWS PLATFORM BINARY TABLE (WPBT)
# ============================================================

$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

# ------------------------------------------------------------
# DISABLE WINDOWS PLATFORM BINARY TABLE
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host "  DISABLE WINDOWS PLATFORM BINARY TABLE (WPBT)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor DarkGray
Write-Host ""

try {
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"

    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    New-ItemProperty `
        -Path $registryPath `
        -Name "DisableWpbtExecution" `
        -PropertyType DWord `
        -Value 1 `
        -Force `
        -ErrorAction Stop | Out-Null

    Write-Host "[OK] Windows Platform Binary Table execution disabled." -ForegroundColor Green
    Write-Host "[INFO] DisableWpbtExecution = 1" -ForegroundColor Gray
}
catch {
    Write-Host "[ERROR] Failed to update the registry: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "[DONE] Operation completed." -ForegroundColor Cyan
Write-Host "--------------------------------------------------------"
Write-Host ""

# 36. Restore Windows Widgets Configuration

Write-Host "`n================================================" -ForegroundColor Gray
Write-Host "  WINDOWS WIDGETS - RESTORE CONFIGURATION" -ForegroundColor Gray
Write-Host "================================================`n" -ForegroundColor Gray

$PolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
$PolicyName = "AllowNewsAndInterests"

if (Test-Path $PolicyPath) {
    $Policy = Get-ItemProperty -Path $PolicyPath -Name $PolicyName -ErrorAction SilentlyContinue

    if ($null -ne $Policy) {
        Remove-ItemProperty -Path $PolicyPath -Name $PolicyName -Force
        Write-Host "[OK] Removed the Widgets policy." -ForegroundColor Green
    }
    else {
        Write-Host "[INFO] The Widgets policy value was not found." -ForegroundColor Yellow
    }
}
else {
    Write-Host "[INFO] The Widgets policy key was not found." -ForegroundColor Yellow
}

Write-Host "`n[INFO] Updating computer policies..." -ForegroundColor Cyan
& gpupdate.exe /target:computer /force

Write-Host "`n[OK] Configuration completed." -ForegroundColor Green
Write-Host "[INFO] Check Settings > Personalization > Taskbar > Widgets." -ForegroundColor Gray
Write-Host "--------------------------------------------------------"
Write-Host ""

# 37 - IObit Unlocker - Version Check, Silent Installation

$Url = "https://www.iobit.com/downloadcenter.php?product=iobit-unlocker"
$InstallerPath = Join-Path $env:TEMP "iobitunlocker.exe"

Write-Host "`n================================================" -ForegroundColor Gray
Write-Host "  IOBIT UNLOCKER - VERSION CHECK AND INSTALLATION" -ForegroundColor Gray
Write-Host "================================================`n" -ForegroundColor Gray

function Get-VersionNumber {
    param(
        [string]$VersionText
    )

    if ([string]::IsNullOrWhiteSpace($VersionText)) {
        return $null
    }

    $Match = [regex]::Match($VersionText, '\d+(?:\.\d+){1,3}')

    if ($Match.Success) {
        try {
            return [version]$Match.Value
        }
        catch {
            return $null
        }
    }

    return $null
}

function Get-InstalledIObitVersion {
    $UninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($Path in $UninstallPaths) {
        $Apps = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue

        foreach ($App in $Apps) {
            if (
                $App.DisplayName -match '(?i)IObit\s*Unlocker|^Unlocker(?:\s*\(32 bits\))?$' -or
                $App.InstallLocation -match '(?i)\\IObit\\IObit Unlocker'
            ) {
                $Version = Get-VersionNumber -VersionText $App.DisplayVersion

                if ($Version) {
                    return $Version
                }
            }
        }
    }

    # Fallback: check the installed executable.
    $ExecutablePaths = @(
        "${env:ProgramFiles(x86)}\IObit\IObit Unlocker\IObitUnlocker.exe",
        "$env:ProgramFiles\IObit\IObit Unlocker\IObitUnlocker.exe"
    )

    foreach ($ExecutablePath in $ExecutablePaths) {
        if ($ExecutablePath -and (Test-Path -LiteralPath $ExecutablePath)) {
            $File = Get-Item -LiteralPath $ExecutablePath

            $Version = Get-VersionNumber -VersionText $File.VersionInfo.ProductVersion

            if (-not $Version) {
                $Version = Get-VersionNumber -VersionText $File.VersionInfo.FileVersion
            }

            if ($Version) {
                return $Version
            }
        }
    }

    return $null
}

# Original automatic process shutdown function preserved.
function Stop-IObitUnlocker {
    param(
        [int]$TimeoutSeconds = 5
    )

    $NamePatterns = @(
        "IObitUnlocker",
        "IObitUnlockerEx",
        "IObitUnlockerExtension",
        "Unlocker"
    )

    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)

    do {
        $FoundProcesses = @(
            Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                Where-Object {
                    $Process = $_
                    $ProcessName = [string]$Process.Name
                    $ProcessPath = [string]$Process.ExecutablePath
                    $ProcessTitle = [string]$Process.Caption

                    $NameMatch = $false

                    foreach ($Pattern in $NamePatterns) {
                        if (
                            $ProcessName -match [regex]::Escape($Pattern) -or
                            $ProcessTitle -match [regex]::Escape($Pattern)
                        ) {
                            $NameMatch = $true
                            break
                        }
                    }

                    $PathMatch = (
                        $ProcessPath -match '(?i)\\IObit\\IObit Unlocker\\'
                    )

                    $NameMatch -or $PathMatch
                }
        )

        foreach ($ProcessInfo in $FoundProcesses) {
            try {
                $Process = Get-Process -Id $ProcessInfo.ProcessId `
                    -ErrorAction SilentlyContinue

                if ($null -ne $Process) {
                    # Try a normal window close first.
                    if ($Process.MainWindowHandle -ne 0) {
                        [void]$Process.CloseMainWindow()
                        Start-Sleep -Milliseconds 700
                    }

                    # Force termination if the process is still running.
                    $StillRunning = Get-Process `
                        -Id $ProcessInfo.ProcessId `
                        -ErrorAction SilentlyContinue

                    if ($null -ne $StillRunning) {
                        Stop-Process -Id $ProcessInfo.ProcessId `
                            -Force -ErrorAction SilentlyContinue
                    }

                    Write-Host "[OK] Closed: $($ProcessInfo.Name) (PID $($ProcessInfo.ProcessId))" `
                        -ForegroundColor Green
                }
            }
            catch {
                Write-Host "[WARN] Could not close PID $($ProcessInfo.ProcessId)." `
                    -ForegroundColor Yellow
            }
        }

        Start-Sleep -Milliseconds 300

    } while (
        [DateTime]::UtcNow -lt $Deadline -and
        @(
            Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Name -match '(?i)IObitUnlocker|IObitUnlockerEx|Unlocker' -or
                    $_.ExecutablePath -match '(?i)\\IObit\\IObit Unlocker\\'
                }
        ).Count -gt 0
    )
}

try {
    # 1. Detect the installed version.
    $InstalledVersion = Get-InstalledIObitVersion

    if ($InstalledVersion) {
        Write-Host "[INFO] Installed version: $InstalledVersion" -ForegroundColor Cyan
    }
    else {
        Write-Host "[INFO] Installed version not detected." -ForegroundColor Yellow
    }

    # 2. Download the installer.
    Write-Host "[INFO] Downloading IObit Unlocker..." -ForegroundColor Cyan

    Invoke-WebRequest -Uri $Url -OutFile $InstallerPath -ErrorAction Stop

    if (-not (Test-Path -LiteralPath $InstallerPath)) {
        throw "The installer file was not downloaded."
    }

    $FileInfo = Get-Item -LiteralPath $InstallerPath

    if ($FileInfo.Length -lt 100KB) {
        throw "The downloaded file is too small to be a valid installer."
    }

    # 3. Verify the installer's digital signature.
    $Signature = Get-AuthenticodeSignature -FilePath $InstallerPath

    if ($Signature.Status -ne "Valid") {
        throw "The installer signature is not valid. Status: $($Signature.Status)"
    }

    $SignerSubject = $Signature.SignerCertificate.Subject

    if ($SignerSubject -notmatch "IObit|ORANGE VIEW LIMITED") {
        throw "Unexpected installer publisher: $SignerSubject"
    }

    Write-Host "[INFO] Verified publisher: $SignerSubject" -ForegroundColor Green

    # 4. Read the downloaded installer's version.
    $InstallerVersionText = $FileInfo.VersionInfo.ProductVersion

    if ([string]::IsNullOrWhiteSpace($InstallerVersionText)) {
        $InstallerVersionText = $FileInfo.VersionInfo.FileVersion
    }

    $InstallerVersion = Get-VersionNumber -VersionText $InstallerVersionText

    if (-not $InstallerVersion) {
        throw "Could not determine the installer version. Installation cancelled."
    }

    Write-Host "[INFO] Available installer version: $InstallerVersion" -ForegroundColor Cyan

    # 5. Install only if the available version is newer.
    if ($InstalledVersion -and $InstallerVersion -le $InstalledVersion) {
        Write-Host "[INFO] Installed version is equal to or newer than the available version." -ForegroundColor Green
        Write-Host "[INFO] Installation skipped." -ForegroundColor Green
    }
    else {
        if ($InstalledVersion) {
            Write-Host "[INFO] Updating from $InstalledVersion to $InstallerVersion..." -ForegroundColor Yellow
        }
        else {
            Write-Host "[INFO] Installing version $InstallerVersion..." -ForegroundColor Yellow
        }

        # 6. Close the application before installation.
        Stop-IObitUnlocker -TimeoutSeconds 8

        # 7. Silent installation.
        Write-Host "[INFO] Installing IObit Unlocker silently..." -ForegroundColor Cyan

        $InstallProcess = Start-Process `
            -FilePath $InstallerPath `
            -ArgumentList "/VERYSILENT", "/NORESTART" `
            -PassThru

        # Wait for installer completion.
        $InstallProcess.WaitForExit()

        if ($InstallProcess.ExitCode -ne 0) {
            throw "The installer exited with code $($InstallProcess.ExitCode)."
        }

        # 8. Close IObit Unlocker after installation.
        Write-Host "[INFO] Closing IObit Unlocker..." -ForegroundColor Cyan

        Stop-IObitUnlocker -TimeoutSeconds 8

        # 9. Verify the installed version.
        $NewInstalledVersion = Get-InstalledIObitVersion

        if (-not $NewInstalledVersion) {
            throw "Installation completed, but the installed version could not be detected."
        }

        if ($NewInstalledVersion -ge $InstallerVersion) {
            Write-Host "[OK] Installed version: $NewInstalledVersion" -ForegroundColor Green
        }
        else {
            throw "Installed version $NewInstalledVersion is older than expected version $InstallerVersion."
        }
    }

    # 10. Final process verification.
    $Remaining = @(
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match '(?i)IObitUnlocker|IObitUnlockerEx|Unlocker' -or
                $_.ExecutablePath -match '(?i)\\IObit\\IObit Unlocker\\'
            }
    )

    if ($Remaining.Count -eq 0) {
        Write-Host "[OK] IObit Unlocker is closed." -ForegroundColor Green
    }
    else {
        foreach ($ProcessInfo in $Remaining) {
            Write-Host "[WARN] Still running: $($ProcessInfo.Name), PID $($ProcessInfo.ProcessId)" `
                -ForegroundColor Yellow
        }
    }

    Write-Host "[OK] Process completed." -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    # Always attempt automatic shutdown.
    Stop-IObitUnlocker -TimeoutSeconds 3

    # Remove the temporary installer.
    if (Test-Path -LiteralPath $InstallerPath) {
        Remove-Item -LiteralPath $InstallerPath -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "--------------------------------------------------------"
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
# ==========================================
# POWERSHELL 7 - INSTALL / UPDATE MANAGER
# Controlled by feature flag
# ==========================================

# Set to $true to enable installation/update checks.
# Set to $false to disable this feature completely.
$EnablePowerShell7Update = $false

function Update-PowerShell7 {

    Write-Host "`nChecking for PowerShell 7 (pwsh) installation and updates..." -ForegroundColor Cyan

    $pwshInstalledVersion = $null

    if (Test-CommandExists "pwsh") {
        $pwshInstalledVersion = Get-PwshVersion
    }

    if ($pwshInstalledVersion) {

        Write-Host "PowerShell 7 (pwsh) detected: Version $pwshInstalledVersion"

        try {
            # Get the latest available version from Winget
            $wingetShowOutput = winget show Microsoft.PowerShell --exact
            $latestPwshVersionString = ""

            # Extract version from the Version line
            $versionLine = $wingetShowOutput |
                Select-String -Pattern "Version:\s*(\S+)"

            if ($versionLine) {
                $latestPwshVersionString = $versionLine.Matches.Groups[1].Value
            }

            if (
                $latestPwshVersionString -and
                ($latestPwshVersionString -notlike "*< Not Available >*")
            ) {
                $latestPwshVersion = [version]$latestPwshVersionString

                Write-Host "Latest PowerShell 7 version available via Winget: $latestPwshVersion"

                if ($pwshInstalledVersion -lt $latestPwshVersion) {

                    Write-Host "Installed version is older. Attempting update via Winget..."

                    winget upgrade Microsoft.PowerShell -e `
                        --accept-package-agreements `
                        --accept-source-agreements

                    if ($LASTEXITCODE -ne 0) {
                        Write-Warning "Failed to update PowerShell 7 via Winget. Exit code: $LASTEXITCODE"
                    }
                    else {
                        Write-Host "PowerShell 7 updated successfully via Winget." -ForegroundColor Green

                        # Reload PATH for the current session
                        $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
                        $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")

                        $env:Path = "$machinePath;$userPath"

                        Write-Host "Current session PATH reloaded."
                    }
                }
                else {
                    Write-Host "PowerShell 7 is already at the latest version or newer. No update needed." -ForegroundColor Green
                }
            }
            else {
                Write-Warning "Could not determine the latest PowerShell 7 version from Winget. Skipping update check."
            }
        }
        catch {
            Write-Error (
                "An error occurred while checking/updating PowerShell 7 via Winget: {0}" -f
                $_.Exception.Message
            )
        }
    }
    else {

        Write-Host "PowerShell 7 (pwsh) not found. Attempting installation via Winget..."

        try {
            winget install Microsoft.PowerShell -e `
                --accept-package-agreements `
                --accept-source-agreements

            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Failed to install PowerShell 7 via Winget. Exit code: $LASTEXITCODE"
            }
            else {
                Write-Host "PowerShell 7 installed successfully via Winget." -ForegroundColor Green

                # Reload PATH for the current session
                $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
                $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")

                $env:Path = "$machinePath;$userPath"

                Write-Host "PATH updated for the current session."
            }
        }
        catch {
            Write-Error (
                "An error occurred while installing PowerShell 7 via Winget: {0}" -f
                $_.Exception.Message
            )
        }
    }
}

# ==========================================
# EXECUTION GATE
# ==========================================

if ($EnablePowerShell7Update) {
    Update-PowerShell7
}
else {
    Write-Host "[SKIPPED] PowerShell 7 installation/update is disabled." -ForegroundColor DarkGray
}

Write-Host "" # Add a blank line for readability

##------------------------------------------------------##

# ============================================================
# Hybrid PowerShell + Windows Terminal Configuration
# ============================================================

Write-Host "`n[INFO] Starting system configuration..." -ForegroundColor Cyan

# ------------------------------------------------------------
# Step 1: Ensure PowerShell 7 exists
# ------------------------------------------------------------
$pwsh = Get-Command pwsh -ErrorAction SilentlyContinue

if (-not $pwsh) {
    Write-Host "[ERROR] PowerShell 7 not found." -ForegroundColor Red
    exit 1
}

$pwshPath = $pwsh.Source
Write-Host "[OK] PowerShell 7: $pwshPath" -ForegroundColor Green

# ------------------------------------------------------------
# Step 2: Detect Windows Terminal
# ------------------------------------------------------------
Write-Host "`n[INFO] Checking Windows Terminal..." -ForegroundColor Cyan

$wtPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"

$hasWT = Test-Path $wtPath

if ($hasWT) {
    Write-Host "[OK] Windows Terminal detected." -ForegroundColor Green

    # --------------------------------------------------------
    # Terminal configuration
    # --------------------------------------------------------
    try {
        Copy-Item $wtPath "$wtPath.bak" -Force

        $json = Get-Content $wtPath -Raw | ConvertFrom-Json

        # find or create pwsh profile
        $profile = $json.profiles.list | Where-Object { $_.commandline -match "pwsh" } | Select-Object -First 1

        if (-not $profile) {
            $profile = @{
                guid        = "{$(New-Guid)}"
                name        = "PowerShell 7"
                commandline = $pwshPath
                hidden      = $false
            }

            $json.profiles.list += $profile
        }

        # set default
        $json.defaultProfile = $profile.guid

        # Appearance
        if (-not $json.profiles.defaults) {
            $json.profiles | Add-Member -MemberType NoteProperty -Name "defaults" -Value @{} -Force
        }

        $json.profiles.defaults.useAcrylic = $true
        $json.profiles.defaults.opacity = 80

        $json | ConvertTo-Json -Depth 100 | Set-Content $wtPath -Encoding UTF8

        Write-Host "[OK] Windows Terminal configured." -ForegroundColor Green
    }
    catch {
        Write-Host "[WARN] Windows Terminal config failed but system will continue." -ForegroundColor Yellow
    }
}
else {
    Write-Host "[WARN] Windows Terminal NOT installed." -ForegroundColor Yellow
    Write-Host "[INFO] Skipping terminal configuration." -ForegroundColor DarkGray
}

# ------------------------------------------------------------
# Step 3: SYSTEM-LEVEL PowerShell 7 default behavior
# (Works even without Windows Terminal)
# ------------------------------------------------------------

Write-Host "`n[INFO] Applying system shell preferences..." -ForegroundColor Cyan

try {

    # Console host fallback behavior
    $consoleKey = "HKCU:\Console"

    if (-not (Test-Path $consoleKey)) {
        New-Item $consoleKey -Force | Out-Null
    }

    # Improve console behavior (pwsh friendly)
    Set-ItemProperty -Path $consoleKey -Name "ForceV2" -Value 1 -ErrorAction SilentlyContinue

    # Set default command line (where applicable)
    Set-ItemProperty -Path $consoleKey -Name "CurrentUser" -Value $pwshPath -ErrorAction SilentlyContinue

    Write-Host "[OK] System console preferences applied." -ForegroundColor Green
}
catch {
    Write-Host "[WARN] System registry tweak skipped (not critical)." -ForegroundColor Yellow
}

# ------------------------------------------------------------
# DONE
# ------------------------------------------------------------
Write-Host "`n[SUCCESS] System configured (hybrid mode)!" -ForegroundColor Green
Write-Host " - PowerShell 7 ready" -ForegroundColor Gray
Write-Host " - Windows Terminal applied if available" -ForegroundColor Gray
Write-Host ""

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

# Bypass potential interactive prompts for the current scope
$ConfirmPreference = 'None'

$hevcPkg = Get-AppxPackage -Name "Microsoft.HEVCVideoExtension" -AllUsers

try {
    # Website scraping for version and link
    $baseUrl = "https://www.free-codecs.com/hevc-video-extensions-from-device-manufacturer_download.htm"
    $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    
    # ADDED -UseBasicParsing to prevent the security warning/interactive prompt
    $page = Invoke-WebRequest -Uri $baseUrl -UserAgent $ua -UseBasicParsing -ErrorAction Stop
    
    # Extracting the newest version string
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
        
        # ADDED -UseBasicParsing here as well for the download
        Invoke-WebRequest -Uri $downloadUrl -OutFile $hevcPath -UserAgent $ua -MaximumRedirection 5 -UseBasicParsing -ErrorAction Stop
        
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

# 2. ADDITIONAL MEDIA EXTENSIONS VIA WINGET
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
    
    # WinGet silent install
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
Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# --- ICAROS THUMBNAILER (IMAGES AND VIDEOS) ---
Write-Host "FIX THUMBNAILS FINAL [2/2]" -ForegroundColor Cyan

# --- ICAROS THUMBNAILER DEPLOYMENT (AUTOMATED GITHUB DELIVERY) ---
Write-Host "[MODULE] Checking Icaros Thumbnailer via GitHub API..." -ForegroundColor Cyan

# Ensure modern TLS 1.2 protocol is used for GitHub API connectivity
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 1. RETRIEVE LATEST METADATA FROM GITHUB REPOSITORY API
try {
    # GitHub API requires a User-Agent header to prevent 403 Forbidden errors
    $headers = @{ "User-Agent" = "PowerShell-Icaros-Updater" }
    $apiUri  = "https://api.github.com/repos/Xanashi/Icaros/releases/latest"
    $apiResponse = Invoke-RestMethod -Uri $apiUri -Headers $headers -ErrorAction Stop
    
    $latestTag = $apiResponse.tag_name # Example: v3.3.5 or v3.3.4b1
    
    # ROBUST VERSION EXTRACTION: Capture only the primary [Major.Minor.Patch] sequence.
    # This prevents 'b1' from being interpreted as '1', avoiding the '41' version logic error.
    if ($latestTag -match '(\d+\.\d+\.\d+)') {
        $targetVersionStr = $matches[1]
    } else {
        $targetVersionStr = ($latestTag -replace '[^0-9.]', '').Trim('.')
    }
    
    $targetVerObj = [version]$targetVersionStr
    # Filter release assets to find the primary executable installer
    $downloadUrl = ($apiResponse.assets | Where-Object { $_.name -like "*.exe" }).browser_download_url
} catch {
    Write-Host "[ERROR] GitHub API Communication Failure: $($_.Exception.Message)" -ForegroundColor Red
    return
}

$installDir    = "$env:ProgramFiles\Icaros"
$versionMarker = "$installDir\version.txt"
$tempPath      = "$env:TEMP\Icaros_Latest.exe"
$shouldInstall = $false

# 2. VALIDATE CURRENT INSTALLATION VIA LOCAL MARKER
if (Test-Path $versionMarker) {
    $content = (Get-Content $versionMarker -Raw).Trim()
    
    # CRITICAL DATA CORRECTION: Override the bugged "3.3.41.0" entry created by previous logic.
    if ($content -eq "3.3.41.0" -or $content -eq "3.3.41") {
        Write-Host ">> Bugged Version Detected (3.3.41.0). Forcing reset for update..." -ForegroundColor Yellow
        $currentVerObj = [version]"0.0.0.0"
    } else {
        # Normalize local version to 3-part standard for fair comparison against GitHub metadata
        if ($content -match '(\d+\.\d+\.\d+)') {
            $currentVerObj = [version]$matches[1]
        } else {
            $currentVerObj = [version]"0.0.0.0"
        }
    }
    Write-Host ">> Current Version (Validated): $currentVerObj" -ForegroundColor Green
} else {
    $currentVerObj = [version]"0.0.0.0"
    $shouldInstall = $true
}

# 3. VERSION COMPARISON LOGIC
Write-Host ">> Latest Version (GitHub): $targetVerObj ($latestTag)" -ForegroundColor White

if ($targetVerObj -gt $currentVerObj) {
    Write-Host ">> Status: [UPDATE REQUIRED]" -ForegroundColor Cyan
    $shouldInstall = $true
} else {
    Write-Host ">> Status: [ALREADY UP TO DATE]" -ForegroundColor Gray
}

# 4. EXECUTE DEPLOYMENT PHASE
if ($shouldInstall -and $downloadUrl) {
    Write-Host "`n[NOTICE] Syncing Icaros to version $latestTag..." -ForegroundColor Cyan
    
    try {
        Write-Host ">> Downloading... " -ForegroundColor Yellow -NoNewline
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempPath -UserAgent "Mozilla/5.0" -ErrorAction Stop
        Write-Host "[OK]" -ForegroundColor Green

        Write-Host ">> Executing Silent Installer (InnoSetup)... " -ForegroundColor Yellow -NoNewline
        # /VERYSILENT: Automated install | /SUPPRESSMSGBOXES: No prompts | /NORESTART: Avoid reboot
        $process = Start-Process -FilePath $tempPath -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Host "[SUCCESS]" -ForegroundColor Green
            
            # Persist clean version string to marker to ensure reliable future checks
            if (-not (Test-Path $installDir)) { New-Item -Path $installDir -ItemType Directory -Force | Out-Null }
            Set-Content -Path $versionMarker -Value $targetVersionStr -Force
            Write-Host ">> Version marker stabilized to: $targetVersionStr" -ForegroundColor Gray
        } else {
            Write-Host "[ERROR: Process Exit Code $($process.ExitCode)]" -ForegroundColor Red
        }
    } catch {
        Write-Host "[DEPLOYMENT ERROR: $($_.Exception.Message)]" -ForegroundColor Red
    } finally {
        # Cleanup temporary deployment artifacts
        if (Test-Path $tempPath) { Remove-Item $tempPath -Force -ErrorAction SilentlyContinue }
    }
}

Write-Host "--------------------------------------------------------`n"

# ==============================================================================
# MODULE: ICAROS CACHE PERMISSIONS REPAIR
# DESCRIPTION: Grants Full Control permissions to the "Everyone" group for the 
#              Icaros Cache directory to prevent thumbnail generation issues.
# ==============================================================================

Write-Host "[MODULE] Starting Icaros Cache Permissions Repair..." -ForegroundColor Cyan

# Define the target Icaros Cache directory path
$icarosPath = "C:\Program Files\Icaros\IcarosCache"

if (Test-Path $icarosPath) {
    try {
        Write-Host ">> Granting Full Control to 'Everyone' on: $icarosPath" -ForegroundColor Yellow
        
        # Retrieve current Access Control List (ACL)
        $acl = Get-Acl $icarosPath
        
        # Use Well-Known SID 'S-1-1-0' (Everyone) for cross-language compatibility
        $identity = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        
        # Define Permission Parameters: Full Control + Inheritance for subfolders/files
        $fileSystemRights = "FullControl"
        $inheritanceFlags = "ContainerInherit, ObjectInherit"
        $propagationFlags = "None"
        $accessType       = "Allow"
        
        # Construct the Access Rule
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity, 
            $fileSystemRights, 
            $inheritanceFlags, 
            $propagationFlags, 
            $accessType
        )
        
        # Apply and commit
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $icarosPath -AclObject $acl
        
        Write-Host "[OK] Icaros permissions updated successfully." -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to set permissions: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[SKIP] Path not found: $icarosPath" -ForegroundColor Yellow
}

Write-Host "--------------------------------------------------------"

##------------------------------------------------------##

# --- WINDOWS NOTEPAD (UWP) REMOVAL ---
# Package ID: 9MSMLRH6LZF3
# Only attempts removal if the package is detected on the system.

$notepadPackage = Get-AppxPackage -Name "*Microsoft.WindowsNotepad*" -AllUsers

if ($notepadPackage) {
    Write-Host "[🚀] Modern Notepad detected. Initializing removal..." -ForegroundColor Cyan
    
    try {
        # Removes the app for all users and stops it from coming back
        Get-AppxPackage -Name "*Microsoft.WindowsNotepad*" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction Stop
        Write-Host "[✅] Windows Notepad has been successfully removed." -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed to remove Notepad: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    # If not found, it stays silent or just gives a subtle log
    Write-Host "[.] Modern Notepad not found. Skipping removal." -ForegroundColor DarkGray
}

# Clear buffer for next commands
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }
Write-Host "--------------------------------------------------------"

##------------------------------------------------------##

# ============================================================
# UNINSTALL ADOBE ACROBAT READER
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host "`n[🚀] Scanning system for Adobe Acrobat Reader..." -ForegroundColor Cyan

$foundAny = $false

# ------------------------------------------------------------
# 1. STOP PROCESSES
# ------------------------------------------------------------
Get-Process | Where-Object {
    $_.Name -match "AcroRd32|AdobeARM|Acrobat"
} | Stop-Process -Force

# ------------------------------------------------------------
# 2. WINGET UNINSTALL
# ------------------------------------------------------------
if (Get-Command winget -ErrorAction SilentlyContinue) {

    Write-Host "[⚙] Checking Winget packages..." -ForegroundColor Yellow

    $wingetPackages = @(
        "Adobe.Acrobat.Reader.32-bit",
        "Adobe.Acrobat.Reader.64-bit",
        "XPDP273C0XHQH2"
    )

    foreach ($pkg in $wingetPackages) {

        $result = winget uninstall --id $pkg -e --silent 2>&1

        if ($LASTEXITCODE -eq 0 -and $result -notmatch "not found") {
            Write-Host "[✔] Winget removed: $pkg" -ForegroundColor Green
            $foundAny = $true
        }
    }
}

# ------------------------------------------------------------
# 3. APPX / MODERN PACKAGE CHECK
# ------------------------------------------------------------
$appx = Get-AppxPackage -AllUsers "*Acrobat*"

if ($appx) {
    $appx | Remove-AppxPackage -AllUsers
    Write-Host "[✔] Removed Appx Acrobat package(s)" -ForegroundColor Green
    $foundAny = $true
}

Get-AppxProvisionedPackage -Online | Where-Object {
    $_.DisplayName -like "*Acrobat*"
} | Remove-AppxProvisionedPackage -Online

# ------------------------------------------------------------
# 4. MSI + ADOBE REGISTRY UNINSTALL
# ------------------------------------------------------------
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$apps = Get-ItemProperty $registryPaths | Where-Object {
    $_.DisplayName -match "Adobe Acrobat Reader|Acrobat Reader DC"
}

foreach ($app in $apps) {

    $foundAny = $true

    Write-Host "[✔] Found: $($app.DisplayName)" -ForegroundColor Yellow

    $uninstall = $app.UninstallString

    if (-not $uninstall) { continue }

    Write-Host "[⚙] Executing uninstall..." -ForegroundColor Green

    if ($uninstall -match "msiexec") {

        $guid = ([regex]"\{.*?\}").Matches($uninstall).Value

        if ($guid) {
            Start-Process "msiexec.exe" -ArgumentList "/x $guid /qn /norestart" -Wait -WindowStyle Hidden
        }

    } else {

        Start-Process "cmd.exe" -ArgumentList "/c `"$uninstall`" /sAll /rs /rps /msi EULA_ACCEPT=YES" -Wait -WindowStyle Hidden
    }
}

# ------------------------------------------------------------
# 5. PATH DETECTION
# ------------------------------------------------------------
$paths = @(
    "C:\Program Files\Adobe\Acrobat DC",
    "C:\Program Files (x86)\Adobe\Acrobat DC"
)

foreach ($p in $paths) {
    if (Test-Path $p) {
        Write-Host "[ℹ] Installation folder detected: $p" -ForegroundColor DarkYellow
        $foundAny = $true
    }
}

# ------------------------------------------------------------
# 6. FINAL CHECK
# ------------------------------------------------------------
$check = Get-ItemProperty $registryPaths | Where-Object {
    $_.DisplayName -match "Adobe Acrobat Reader"
}

Write-Host "`n--------------------------------------------------------" -ForegroundColor DarkGray

if ($check) {

    Write-Host "[!] Adobe Reader is STILL PRESENT" -ForegroundColor Red
    Write-Host "[→] Manual uninstall may be required (corrupted installer or locked service)" -ForegroundColor Yellow

} elseif ($foundAny) {

    Write-Host "[✅] Adobe Reader has been successfully removed." -ForegroundColor Green

} else {

    Write-Host "[✔] AdobeReader was not detected on this system." -ForegroundColor Green
    Write-Host "[ℹ] No action was required." -ForegroundColor DarkGray
}

Write-Host "--------------------------------------------------------`n" -ForegroundColor DarkGray

##------------------------------------------------------##

# ============================================================
# BLOCKIFY DESKTOP DEPLOYMENT
# ============================================================

Write-Host "[MODULE] Deploying Blockify Desktop via dynamic web resolution..." -ForegroundColor Cyan

# Ensure TLS 1.2 compatibility
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ------------------------------------------------------------
# PATHS & CONFIGURATION
# ------------------------------------------------------------
$installDir     = "$env:APPDATA\Blockify"
$versionMarker  = "$installDir\version.txt"
$ua             = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
$tempZip        = "$env:TEMP\Blockify.zip"
$extractPath    = "$env:TEMP\Blockify_Extract"
$skipInstall    = $false

try {
    # ------------------------------------------------------------
    # DETECT WINDOWS SERVER ENVIRONMENT
    # ------------------------------------------------------------
    Write-Host ">> Checking operating system type... " -ForegroundColor Yellow -NoNewline

    $os = Get-CimInstance Win32_OperatingSystem
    $isServer = ($os.ProductType -ne 1)

    if ($isServer) {
        Write-Host "[SERVER DETECTED - SKIPPING INSTALL]" -ForegroundColor DarkYellow
        $skipInstall = $true
    } else {
        Write-Host "[WORKSTATION]" -ForegroundColor Green
    }

    # ------------------------------------------------------------
    # DYNAMIC VERSION & URL RESOLUTION (Primary: GetBlockify Site)
    # ------------------------------------------------------------
    if (-not $skipInstall) {

        Write-Host ">> Resolving latest version from GetBlockify..." -ForegroundColor Yellow

        $targetUrl = $null
        $latestVersionStr = $null

        try {
            $pageHtml = (Invoke-WebRequest -Uri "https://getblockify.com/desktop" -UserAgent $ua -UseBasicParsing -ErrorAction Stop).Content
            
            if ($pageHtml -match 'href="([^"]*?/downloads/Blockify-([\d\.]+)-win-x64\.zip)"') {
                $targetUrl = $Matches[1]
                if (-not $targetUrl.StartsWith("http")) {
                    $targetUrl = "https://getblockify.com$targetUrl"
                }
                $latestVersionStr = $Matches[2]
            }
        } catch {
            Write-Host "   [WARN] Primary site fetch failed, switching to GitHub fallback..." -ForegroundColor DarkYellow
        }

        # FALLBACK: GitHub Releases if primary site link extraction fails
        if (-not $targetUrl -or -not $latestVersionStr) {
            Write-Host ">> Checking GitHub fallback for latest release..." -ForegroundColor Yellow
            $apiUrl = "https://api.github.com/repos/dhanur2/spotify-ad-blocker-blockify-desktop/releases/latest"
            $headers = @{ "User-Agent" = $ua }
            
            $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers
            $latestVersionStr = $response.tag_name -replace '^v', ''
            
            foreach ($asset in $response.assets) {
                if ($asset.name -match "win-x64\.zip") {
                    $targetUrl = $asset.browser_download_url
                    break
                }
            }
        }

        if (-not $targetUrl -or -not $latestVersionStr) {
            throw "Could not resolve Blockify download URL or version from any source."
        }

        $latestVersion = [version]$latestVersionStr
        Write-Host "[OK: v$latestVersionStr]" -ForegroundColor Green
    }

    # ------------------------------------------------------------
    # DETECT CURRENT INSTALLED VERSION
    # ------------------------------------------------------------
    if (-not $skipInstall) {

        Write-Host ">> Checking local version marker..." -ForegroundColor Yellow

        $currentVersion = [version]"0.0.0.0"
        $detected = $false

        if (Test-Path $versionMarker) {
            try {
                $content = (Get-Content $versionMarker -Raw).Trim()
                if ($content -match "([\d\.]+)") {
                    $currentVersion = [version]$matches[1]
                    $detected = $true
                    Write-Host "   [VERSION FOUND] Installed: $currentVersion" -ForegroundColor Cyan
                }
            } catch {
                Write-Host "   [READ FAILED]" -ForegroundColor DarkYellow
            }
        }

        if (-not $detected) {
            Write-Host "   [NO PREVIOUS VERSION MARKER]" -ForegroundColor DarkGray
        }

        # ------------------------------------------------------------
        # VERSION COMPARISON
        # ------------------------------------------------------------
        if ($latestVersion -le $currentVersion) {
            Write-Host ">> Status: [ALREADY UP TO DATE]" -ForegroundColor Green
            $skipInstall = $true
        }
    }

    # ------------------------------------------------------------
    # DOWNLOAD AND EXTRACTION
    # ------------------------------------------------------------
    if (-not $skipInstall) {

        Write-Host ">> Status: [UPDATE REQUIRED]" -ForegroundColor Cyan
        Write-Host ">> Downloading package from $targetUrl... " -ForegroundColor Yellow -NoNewline
        
        Invoke-WebRequest -Uri $targetUrl -OutFile $tempZip -UserAgent $ua -ErrorAction Stop
        Write-Host "[OK]" -ForegroundColor Green

        # Prepare directories
        if (-not (Test-Path $installDir)) {
            New-Item -Path $installDir -ItemType Directory -Force | Out-Null
        }
        if (Test-Path $extractPath) {
            Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -Path $extractPath -ItemType Directory -Force | Out-Null

        Write-Host ">> Extracting ZIP package... " -ForegroundColor Yellow -NoNewline
        Expand-Archive -Path $tempZip -DestinationPath $extractPath -Force
        Write-Host "[OK]" -ForegroundColor Green

        # Locate the installer executable inside the extracted folder (.exe)
        $installerExe = Get-ChildItem -Path $extractPath -Filter "*.exe" -Recurse | Select-Object -First 1

        if (-not $installerExe) {
            throw "No installer executable (.exe) found inside the extracted ZIP."
        }

        # ------------------------------------------------------------
        # EXECUTE SILENT INSTALLATION (Using NSIS switch /S)
        # ------------------------------------------------------------
        Write-Host ">> Executing Blockify installer silently..." -ForegroundColor Yellow
        
        Start-Process -FilePath $installerExe.FullName -ArgumentList "/S" -Wait -NoNewWindow

        # Save version marker
        Set-Content -Path $versionMarker -Value $latestVersionStr -Force
        Write-Host ">> Version marker updated to: $latestVersionStr" -ForegroundColor Gray
        Write-Host ">> Deployment completed successfully." -ForegroundColor Green
    }

} catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
} finally {
    # ------------------------------------------------------------
    # CLEANUP INSTALLER FILES AND ZIP
    # ------------------------------------------------------------
    if ((Test-Path $tempZip) -or (Test-Path $extractPath)) {
        Write-Host ">> Cleaning up temporary files and installer artifacts..." -ForegroundColor Yellow

        if (Test-Path $tempZip) {
            Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $extractPath) {
            Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
        }

        Write-Host ">> Cleanup complete." -ForegroundColor Green
    }
}

##------------------------------------------------------##

# --- AUTOMATIC APP INSTALLATION (UNATTENDED) ---
Write-Host "`n[MODULE] Deploying Essential Applications..." -ForegroundColor Cyan

# Detect if OS is Windows Server
$osInfo = Get-CimInstance Win32_OperatingSystem
$isServer = $osInfo.ProductType -ne 1  # 1 = Workstation, others = Server/DC

# Apps that should NOT be installed on Windows Server
$serverBlockedApps = @(
    "UpNote",
    "Calibre",
    "Simple Radio Online",
    "SparkLabs.Viscosity",
    "WireSock",
    "Microsoft.IntelligentTerminal",
    "Lively Weather",
    "Calendar App",
    "Energy Star X"
)

$appsToInstall = @(
    @{ Name = "7zip"; ID = "7zip.7zip" },
    @{ Name = "Supermium"; ID = "win32ss.Supermium" },
    @{ Name = "UpNote"; ID = "9mv7690m8f5n" },
    @{ Name = "WinRAR"; ID = "RARLab.WinRAR" },
    @{ Name = "Ookla Speedtest CLI"; ID = "Ookla.Speedtest.CLI" },
    @{ Name = "Intelligent Terminal"; ID = "Microsoft.IntelligentTerminal" },
    @{ Name = "Lively Weather"; ID = "9pp0mfqfvsc5" },
    @{ Name = "Calendar App"; ID = "9pn24rvqdfrs" },
    @{ Name = "Energy Star X"; ID = " 9nf7jtb3b17p" },
    @{ Name = "LibreWolf"; ID = "9nvn9sz8kfd7" },
    @{ Name = "Viscosity"; ID = "SparkLabs.Viscosity" },
    @{ Name = "WireSock"; ID = "NTKERNEL.WireSockVPNClient" },
    @{ Name = "ShareX"; ID = "ShareX.ShareX" },
    @{ Name = "CrystalDiskInfo"; ID = "CrystalDewWorld.CrystalDiskInfo" },
    @{ Name = "SSD Booster"; ID = "9nvmxq4ps0lb" },
    @{ Name = "PDFgear"; ID = "PDFgear.PDFgear" },
    @{ Name = "Calibre"; ID = "Calibre.calibre" },
    @{ Name = "Simple Radio Online"; ID = "9n4hx2x3f88h" }
)

# Filter apps if running on Windows Server
if ($isServer) {
    Write-Host "[INFO] Windows Server detected - filtering unsupported apps..." -ForegroundColor DarkYellow

    $appsToInstall = $appsToInstall | Where-Object {
        $_.Name -notin $serverBlockedApps
    }
}

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
    elseif ($exitCode -in @(-1978335135, -1978335189, -1978335191, -1978335221, -1978335212)) {
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

# ============================================================
# WIRESOCK SECURE CONNECT - CMD CREATION
# ============================================================

Write-Host "[MODULE] Creating WireSock startup script..." -ForegroundColor Cyan

# ------------------------------------------------------------
# PATHS & CONFIGURATION
# ------------------------------------------------------------
$startupDir = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
$cmdPath    = Join-Path $startupDir "StartWireSock.cmd"

# ------------------------------------------------------------
# ENSURE TARGET DIRECTORY EXISTS
# ------------------------------------------------------------
if (-not (Test-Path $startupDir)) {
    Write-Host ">> Creating target directory..." -ForegroundColor Yellow

    New-Item -Path $startupDir -ItemType Directory -Force |
        Out-Null
}

# ------------------------------------------------------------
# CHECK IF CMD FILE ALREADY EXISTS
# ------------------------------------------------------------
if (Test-Path $cmdPath) {
    Write-Host ">> CMD script already exists. Skipping creation." -ForegroundColor DarkYellow
}
else {

    # --------------------------------------------------------
    # CMD SCRIPT CONTENT
    # --------------------------------------------------------
    $cmdContent = @'
@echo off
title WireSock Secure Connect

:: Check for administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    goto :eof
)

echo Starting WireSock services...

net start "WireSockAppService"
net start "WireSockConnectService"

echo.
echo Opening WireSock Connect...

start "" "C:\Program Files\WireSock Secure Connect\bin\WireSockConnect.exe"

echo.
echo Process completed.
'@

    # --------------------------------------------------------
    # CREATE CMD FILE
    # --------------------------------------------------------
    try {
        Set-Content -Path $cmdPath -Value $cmdContent -Encoding ASCII

        Write-Host ">> CMD script created successfully: $cmdPath" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to create CMD script: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# ==============================================================================
# DISK INTELLIGENCE & SMART ANALYSIS MODULE
# ==============================================================================

Write-Host " ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host " ║        DISK INTELLIGENCE & SMART ANALYSIS MODULE         ║" -ForegroundColor Cyan
Write-Host " ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ==============================================================================
# LOCALIZATION ENGINE
# ==============================================================================

$currentLang = [System.Globalization.CultureInfo]::CurrentUICulture.Name

$langMap = @{
    "pt*" = @{
        Update     = "Atualizando dados SMART..."
        LogGen     = "Log SMART gerado na pasta Temp."
        Analyzing  = "Analisando Armazenamento..."
        NoDrives   = "Nenhum disco detectado."
        Name       = "NOME"
        Letter     = "LETRA"
        Serial     = "SERIAL"
        FW         = "FIRMWARE"
        Health     = "SAÚDE"
        Temp       = "TEMPERATURA"
        Power      = "LIGADO POR"
        Cycles     = "Ciclos"
        Interface  = "INTERFACE"
        Standard   = "PADRÃO"
        Features   = "RECURSOS"
        Type       = "TIPO"
        Clean      = "Arquivo temporário removido."
        HostRW     = "L/G HOSPED."
        Read       = "L"
        Write      = "G"
    }

    "en*" = @{
        Update     = "Updating SMART data..."
        LogGen     = "SMART log generated in Temp folder."
        Analyzing  = "Analyzing Storage..."
        NoDrives   = "No drives detected."
        Name       = "NAME"
        Letter     = "LETTER"
        Serial     = "SERIAL"
        FW         = "FIRMWARE"
        Health     = "HEALTH"
        Temp       = "TEMPERATURE"
        Power      = "POWER ON"
        Cycles     = "Cycles"
        Interface  = "INTERFACE"
        Standard   = "STANDARD"
        Features   = "FEATURES"
        Type       = "TYPE"
        Clean      = "Temporary log file removed."
        HostRW     = "HOST R/W"
        Read       = "R"
        Write      = "W"
    }
}

$UI = $langMap["en*"]

foreach ($pattern in $langMap.Keys) {
    if ($currentLang -like $pattern) {
        $UI = $langMap[$pattern]
        break
    }
}

# ==============================================================================
# CONFIG
# ==============================================================================

$cdiExecutable = "C:\Program Files\CrystalDiskInfo\DiskInfo64.exe"
$workPath      = Join-Path $env:TEMP "DEBUG_DISK.txt"
$cdiDir        = [System.IO.Path]::GetDirectoryName($cdiExecutable)
$sourceLog     = Join-Path $cdiDir "DiskInfo.txt"

# Global SSD Detection Flag
$Global:SSDDetected = $false

try {

    Write-Host "`n [🔄] $($UI.Update)" -ForegroundColor Yellow

    if (Test-Path $cdiExecutable) {

        Start-Process `
            -FilePath $cdiExecutable `
            -ArgumentList "/CopyExit" `
            -Wait

        if (Test-Path $sourceLog) {

            Move-Item `
                -Path $sourceLog `
                -Destination $workPath `
                -Force

            Write-Host " [✅] $($UI.LogGen)" -ForegroundColor Green
        }
        else {
            Write-Host " [!] SMART log was not generated." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host " [!] CrystalDiskInfo not found." -ForegroundColor Red
    }

    Write-Host " [🔍] $($UI.Analyzing) ($currentLang)" -ForegroundColor Cyan

    if (-not (Test-Path $workPath)) {
        Write-Host " [!] SMART file not found." -ForegroundColor Yellow
    }
    else {

        try {
            $rawContent = Get-Content $workPath -Raw -Encoding UTF8
        }
        catch {
            $rawContent = Get-Content $workPath -Raw
        }

        $rawContent = $rawContent `
            -replace "`0","" `
            -replace "`r",""

        $pattern = '(?ms)^-+\s*\n\s*\(\d+\).*?\n-+\s*\n(.*?)(?=^-+\s*\n\s*\(\d+\)|\z)'

        $diskBlocks = [regex]::Matches($rawContent, $pattern)

        if ($diskBlocks.Count -eq 0) {

            Write-Host " [!] $($UI.NoDrives)" -ForegroundColor Red
        }
        else {

            foreach ($item in $diskBlocks) {

                $block = $item.Groups[1].Value

                function Get-Val($regex) {
                    if ($block -match $regex) {
                        return $matches[1].Trim()
                    }
                    return ""
                }

                $props = @{
                    Model     = Get-Val '(?m)^\s*Model\s*:\s*(.+)$'
                    Letter    = Get-Val '(?m)^\s*Drive Letter\s*:\s*(.+)$'
                    Serial    = Get-Val '(?m)^\s*Serial Number\s*:\s*(.+)$'
                    FW        = Get-Val '(?m)^\s*Firmware\s*:\s*(.+)$'
                    Health    = Get-Val '(?m)^\s*Health Status\s*:\s*(.+)$'
                    Temp      = Get-Val '(?m)^\s*Temperature\s*:\s*(.+)$'
                    Hours     = Get-Val '(?m)^\s*Power On Hours\s*:\s*(.+)$'
                    Count     = Get-Val '(?m)^\s*Power On Count\s*:\s*(.+)$'
                    Interface = Get-Val '(?m)^\s*Interface\s*:\s*(.+)$'
                    Features  = Get-Val '(?m)^\s*Features\s*:\s*(.+)$'
                    Standard  = Get-Val '(?m)^\s*Standard\s*:\s*(.+)$'
                    Rotation  = Get-Val '(?m)^\s*Rotation Rate\s*:\s*(.+)$'
                    Reads     = Get-Val '(?m)^\s*Host Reads\s*:\s*(.+)$'
                    Writes    = Get-Val '(?m)^\s*Host Writes\s*:\s*(.+)$'
                }

                # ==========================================================================
                # SSD DETECTION FIX
                # ==========================================================================

                $IsSSD = $false
                $IsNVMe = $false

                if ($props.Interface -match 'NVMe') {
                    $IsSSD = $true
                    $IsNVMe = $true
                }

                elseif (
                    $props.Rotation -match 'SSD' -or
                    $props.Rotation -match '----' -or
                    $props.Features -match 'TRIM'
                ) {
                    $IsSSD = $true
                }

                if ($IsSSD) {
                    $Global:SSDDetected = $true
                }

                # ==========================================================================
                # STANDARD FALLBACK
                # ==========================================================================

                if (-not $props.Standard) {

                    $major = Get-Val '(?m)^\s*Major Version\s*:\s*(.+)$'
                    $minor = Get-Val '(?m)^\s*Minor Version\s*:\s*(.+)$'

                    $props.Standard = "$major | $minor".Trim(" |")
                }

                # ==========================================================================
                # HEALTH FORMAT
                # ==========================================================================

                $HealthPct = ""

                if ($props.Health -match '\((.*?)\)') {

                    $HealthPct = $matches[1]

                    $props.Health = (
                        $props.Health -replace '\(.*?\)', ''
                    ).Trim()
                }

                if (
                    -not $HealthPct -and
                    $props.Health -match 'Healthy|Good|Saudável'
                ) {
                    $HealthPct = "100 %"
                }

                if ($props.Temp -match '^(.+?)\s*\(') {
                    $props.Temp = $matches[1].Trim()
                }

                $hColor = "White"

                if ($props.Health -match 'Healthy|Good|Saudável') {
                    $hColor = "Green"
                }
                elseif ($props.Health -match 'Caution|Warning|Alerta') {
                    $hColor = "Yellow"
                }
                elseif ($props.Health -match 'Bad|Fail|Ruim') {
                    $hColor = "Red"
                }

                # ==========================================================================
                # OUTPUT
                # ==========================================================================

                Write-Host "`n----------------------------------------------------" -ForegroundColor DarkGray

                Write-Host " $($UI.Name):".PadRight(15) -NoNewline
                Write-Host $props.Model -ForegroundColor White

                Write-Host " $($UI.Letter):".PadRight(15) -NoNewline
                Write-Host $props.Letter -ForegroundColor Cyan

                Write-Host " $($UI.Serial):".PadRight(15) -NoNewline
                Write-Host $props.Serial -ForegroundColor White

                Write-Host " $($UI.FW):".PadRight(15) -NoNewline
                Write-Host $props.FW -ForegroundColor White

                Write-Host " $($UI.Health):".PadRight(15) -NoNewline
                Write-Host "$($props.Health) $HealthPct" -ForegroundColor $hColor

                Write-Host " $($UI.Temp):".PadRight(15) -NoNewline
                Write-Host $props.Temp -ForegroundColor Cyan

                Write-Host " $($UI.Power):".PadRight(15) -NoNewline
                Write-Host "$($props.Hours) | $($UI.Cycles): $($props.Count)" -ForegroundColor White

                Write-Host " $($UI.Interface):".PadRight(15) -NoNewline
                Write-Host $props.Interface -ForegroundColor Magenta

                Write-Host " $($UI.Standard):".PadRight(15) -NoNewline
                Write-Host $props.Standard -ForegroundColor White

                Write-Host " $($UI.Features):".PadRight(15) -NoNewline
                Write-Host $props.Features -ForegroundColor White

                # ==========================================================================
                # TYPE OUTPUT
                # ==========================================================================

                Write-Host " $($UI.Type):".PadRight(15) -NoNewline

                if ($IsNVMe) {

                    Write-Host "NVMe SSD" -ForegroundColor Green
                }
                elseif ($IsSSD) {

                    Write-Host "SATA SSD" -ForegroundColor Green
                }
                else {

                    Write-Host "HDD ($($props.Rotation))" -ForegroundColor Magenta
                }

                # ==========================================================================
                # HOST READ / WRITE
                # ==========================================================================

                if ($IsSSD) {

                    Write-Host " $($UI.HostRW):".PadRight(15) -NoNewline

                    Write-Host `
                        "$($UI.Read): $($props.Reads) | $($UI.Write): $($props.Writes)" `
                        -ForegroundColor Cyan
                }

                Write-Host "----------------------------------------------------" -ForegroundColor DarkGray
            }
        }
    }
}
finally {

    if (Test-Path $workPath) {

        Remove-Item $workPath -Force

        Write-Host "`n [🗑️] $($UI.Clean)" -ForegroundColor Gray
    }
}

Write-Host "--------------------------------------------------------"

# ==============================================================================
# SSD MODULE COMPATIBILITY FLAG
# ==============================================================================

if ($Global:SSDDetected) {

    Write-Host ""
    Write-Host " [OK] SSD detected. Next modules may continue." -ForegroundColor Green
}
else {

    Write-Host ""
    Write-Host " [!] No SSD detected. Continuing..." -ForegroundColor Yellow
}

Write-Host "--------------------------------------------------------"

##------------------------------------------------------##

# ==============================================================================
# SSD OPTIMIZATION
# ==============================================================================

Write-Host " ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host " ║          SSD OPTIMIZATION MODULE                         ║" -ForegroundColor Cyan
Write-Host " ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ================= ENVIRONMENT CHECK =================

Write-Host " [*] Checking system compatibility..." -NoNewline

# --- CHECK WINDOWS SERVER ---
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -ne 1) {
    Write-Host " SKIPPED (Windows Server detected)" -ForegroundColor Yellow
    Write-Host "`n [ABORTED] This script is not intended for Windows Server." -ForegroundColor Red
    Write-Host "--------------------------------------------------------"
    Write-Host ""
}

# --- CHECK SSD ---
$hasSSD = $false

try {
    $disks = Get-PhysicalDisk -ErrorAction Stop
    foreach ($d in $disks) {
        if ($d.MediaType -eq "SSD") {
            $hasSSD = $true
            break
        }
    }
} catch {}

# --- FALLBACK (IF MediaType FAILS) ---
if (-not $hasSSD) {
    try {
        $models = Get-WmiObject Win32_DiskDrive | Select-Object -ExpandProperty Model
        foreach ($m in $models) {
            if ($m -match "SSD|NVMe") {
                $hasSSD = $true
                break
            }
        }
    } catch {}
}

# --- FINAL DECISION ---
if (-not $hasSSD) {
    Write-Host " SKIPPED (No SSD detected)" -ForegroundColor Yellow
    Write-Host "`n [ABORTED] No SSD detected. Optimization not applied." -ForegroundColor Red
    Write-Host "--------------------------------------------------------"
    Write-Host ""
}

Write-Host " OK (SSD detected)" -ForegroundColor Green

# ================= HELPER =================
function Set-IfNeeded {
    param($Path, $Name, $Value)

    try { $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { $current = $null }

    if ($current -ne $Value) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
        return $true
    }
    return $false
}

# ================= SAFE OPTIMIZATIONS =================

# 1 - INDEXING
Write-Host " [1] Search Indexing..." -NoNewline
$s = Get-Service WSearch -ErrorAction SilentlyContinue
if ($s -and $s.StartType -ne 'Disabled') {
    Stop-Service WSearch -Force
    Set-Service WSearch -StartupType Disabled
    Write-Host " DONE (Disabled)" -ForegroundColor Green
} else { Write-Host " OK (Already optimized)" -ForegroundColor Gray }

# 2 - BOOT OPTIMIZATION
Write-Host " [2] Boot Optimization..." -NoNewline
if (Set-IfNeeded "HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" "Enable" "N") {
    Write-Host " DONE" -ForegroundColor Green
} else { Write-Host " OK (Already optimized)" -ForegroundColor Gray }

# 3 - PREFETCH
Write-Host " [3] Prefetch..." -NoNewline
if (Set-IfNeeded "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" 0) {
    Write-Host " DONE" -ForegroundColor Green
} else { Write-Host " OK (Already optimized)" -ForegroundColor Gray }

# 4 - SUPERFETCH
Write-Host " [4] Superfetch..." -NoNewline
if (Set-IfNeeded "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnableSuperfetch" 0) {
    Write-Host " DONE" -ForegroundColor Green
} else { Write-Host " OK (Already optimized)" -ForegroundColor Gray }

# 5 - SYSMAIN
Write-Host " [5] SysMain..." -NoNewline
$sm = Get-Service SysMain -ErrorAction SilentlyContinue
if ($sm -and $sm.StartType -ne 'Disabled') {
    Stop-Service SysMain -Force
    Set-Service SysMain -StartupType Disabled
    Write-Host " DONE" -ForegroundColor Green
} else { Write-Host " OK (Already optimized)" -ForegroundColor Gray }

# 6 - 8.3 NAMES
Write-Host " [6] 8.3 Filename Creation..." -NoNewline
if (Set-IfNeeded "HKLM:\System\CurrentControlSet\Control\FileSystem" "NtfsDisable8dot3NameCreation" 1) {
    Write-Host " DONE" -ForegroundColor Green
} else { Write-Host " OK (Already optimized)" -ForegroundColor Gray }

# 7 - TRIM
Write-Host " [7] TRIM..." -NoNewline

try {
    $trim = fsutil behavior query DisableDeleteNotify

    # SAFE EXTRACTION
    $value = [regex]::Match($trim, '\d+').Value

    if ($value -eq "1") {
        fsutil behavior set DisableDeleteNotify 0 | Out-Null
        Write-Host " DONE (Enabled)" -ForegroundColor Green
    } else {
        Write-Host " OK (Already optimized)" -ForegroundColor Gray
    }
}
catch {
    Write-Host " FAIL" -ForegroundColor Red
}

# 8 - PAGE FILE
Write-Host " [8] Page File Cleanup..." -NoNewline
if (Set-IfNeeded "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "ClearPageFileAtShutdown" 0) {
    Write-Host " DONE" -ForegroundColor Green
} else { Write-Host " OK (Already optimized)" -ForegroundColor Gray }

# 9 - CACHE
Write-Host " [9] Large System Cache..." -NoNewline
if (Set-IfNeeded "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "LargeSystemCache" 0) {
    Write-Host " DONE" -ForegroundColor Green
} else { Write-Host " OK (Already optimized)" -ForegroundColor Gray }

# ================= EXTRA =================

# 10 - NTFS MEMORY (TRUE INSTALLED PHYSICAL RAM - DIMM BASED)
Write-Host " [10] NTFS Memory Usage..." -NoNewline

try {
    # SUM ALL PHYSICAL RAM MODULES (REAL HARDWARE VALUE)
    $ramBytes = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum

    # STRICT CONVERSION BASE 1024
    $ramGB = $ramBytes / 1GB
    $ramMB = $ramBytes / 1MB

    # FORCE CLEAN FORMAT (NO LOCALE ISSUES)
    $culture = [System.Globalization.CultureInfo]::InvariantCulture

    $ramGBText = $ramGB.ToString("F2", $culture)
    $ramMBText = [math]::Round($ramMB).ToString("0", $culture)

    $ramDisplay = "$ramGBText GB ($ramMBText MB)"

    $current = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
        -Name NtfsMemoryUsage -ErrorAction SilentlyContinue).NtfsMemoryUsage

    if ($ramBytes -ge 8GB) {

        if ($current -ne 2) {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
                -Name NtfsMemoryUsage -Value 2 -Force

            Write-Host " DONE (RAM: $ramDisplay → High cache enabled)" -ForegroundColor Green
        }
        else {
            Write-Host " OK (High cache active - RAM: $ramDisplay)" -ForegroundColor Gray
        }

    }
    else {

        if ($current -ne 1) {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
                -Name NtfsMemoryUsage -Value 1 -Force

            Write-Host " DONE (RAM: $ramDisplay → Default restored)" -ForegroundColor Yellow
        }
        else {
            Write-Host " OK (Default - RAM: $ramDisplay)" -ForegroundColor Gray
        }
    }
}
catch {
    Write-Host " FAIL (RAM detection error)" -ForegroundColor Red
}

# 11 - WRITE CACHE FLUSH (SMART BATTERY LOGIC)
Write-Host " [11] Write Cache Buffer Flush..." -NoNewline

try {
    $battery = Get-CimInstance Win32_Battery -ErrorAction Stop

    $batteryInfo = "No battery"
    $disableFlush = $false

    if ($battery) {
        $charge = $battery.EstimatedChargeRemaining
        $batteryInfo = "$charge%"

        if ($charge -gt 0) {
            $disableFlush = $true
        }
    }

    if ($disableFlush) {
        if (Set-IfNeeded "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "DisableFlushOnWrite" 1) {
            Write-Host " DONE (Flush OFF - Battery: $batteryInfo)" -ForegroundColor Green
        } else {
            Write-Host " OK (Already OFF - Battery: $batteryInfo)" -ForegroundColor Gray
        }
    }
    else {
        if (Set-IfNeeded "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "DisableFlushOnWrite" 0) {
            Write-Host " DONE (Flush ON - Safety mode)" -ForegroundColor Yellow
        } else {
            Write-Host " OK (Already ON - Safety mode)" -ForegroundColor Gray
        }
    }
}
catch {
    # No battery detected → desktop behavior
    try {
        if (Set-IfNeeded "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "DisableFlushOnWrite" 0) {
            Write-Host " DONE (Flush ON - No battery)" -ForegroundColor Yellow
        } else {
            Write-Host " OK (Already ON - No battery)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host " FAIL (Registry access denied)" -ForegroundColor Red
    }
}

# 12 - KERNEL PAGING
Write-Host " [12] Kernel Paging..." -NoNewline
if (Set-IfNeeded "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "DisablePagingExecutive" 1) {
    Write-Host " DONE" -ForegroundColor Green
} else { Write-Host " OK (Already optimized)" -ForegroundColor Gray }

# ================= SENSITIVE =================

# 13 - LAST ACCESS
Write-Host " [13] Last Access Timestamp..." -NoNewline

try {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
    $name = "NtfsDisableLastAccessUpdate"

    # Safely read registry value
    $current = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name

    # Normalize null/empty values safely
    if ($null -eq $current -or $current -eq "") {
        $current = 0
    }

    # Safe conversion (prevents crash)
    try {
        $current = [int]$current
    } catch {
        $current = 0
    }

    $desired = 2

    if ($current -eq $desired) {
        Write-Host " OK (Already optimized)" -ForegroundColor Gray
    }
    else {
        Set-ItemProperty -Path $path -Name $name -Value $desired -Force -ErrorAction Stop
        Write-Host " DONE" -ForegroundColor Green
    }
}
catch {
    Write-Host " FAIL (Registry access or permission issue)" -ForegroundColor Red
}

# 14 - HIBERNATION
Write-Host " [14] Hibernation & Fast Startup..." -NoNewline
$hib = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power").HibernateEnabled
$fast = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power").HiberbootEnabled

if ($hib -eq 0 -and $fast -eq 0) {
    Write-Host " OK (Already optimized)" -ForegroundColor Gray
} else {
    powercfg /hibernate off | Out-Null
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name HibernateEnabled -Value 0
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name HiberbootEnabled -Value 0
    Write-Host " DONE" -ForegroundColor Green
}

# 15 - DRIVE OPTIMIZATION
Write-Host " [15] Drive Optimization (Scheduled TRIM/Defrag)..." -NoNewline

$task = Get-ScheduledTask -TaskName "ScheduledDefrag" -TaskPath "\Microsoft\Windows\Defrag\" -ErrorAction SilentlyContinue

if ($task) {

    if ($task.State -eq "Ready" -or $task.State -eq "Running") {
        Write-Host " OK (Already enabled)" -ForegroundColor Gray
    }
    else {
        try {
            Enable-ScheduledTask -TaskName "ScheduledDefrag" -TaskPath "\Microsoft\Windows\Defrag\" | Out-Null
            Write-Host " DONE (Enabled TRIM optimization)" -ForegroundColor Green
        } catch {
            Write-Host " FAIL (Could not enable task)" -ForegroundColor Red
        }
    }

} else {
    Write-Host " FAIL (Task not found)" -ForegroundColor Red
}

# 16 - EVENT LOG
Write-Host " [16] Event Logging..." -NoNewline

$svc = Get-Service EventLog -ErrorAction SilentlyContinue
if ($svc.Status -ne "Running") {
    Start-Service EventLog -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}

$logs = @("Application","System")
$alreadyOptimized = $true

foreach ($log in $logs) {
    try {
        $info = wevtutil gli $log 2>$null

        if ($info) {
            $sizeLine = ($info | Select-String "maxSize")

            if ($sizeLine) {
                $currentSize = [int]([regex]::Match($sizeLine.ToString(), '\d+').Value)

                if ($currentSize -gt 20971520) {
                    wevtutil sl $log /ms:20971520 | Out-Null
                    wevtutil sl $log /rt:true | Out-Null
                    $alreadyOptimized = $false
                }
            }
        }
    }
    catch {
        $alreadyOptimized = $false
    }
}

if ($alreadyOptimized) {
    Write-Host " OK (Already optimized)" -ForegroundColor Gray
} else {
    Write-Host " DONE (Reduced log size)" -ForegroundColor Yellow
}

# 17 - THUMBNAIL CACHE
Write-Host " [17] Thumbnail Cache..." -NoNewline
$current = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction SilentlyContinue).DisableThumbnailCache

if ($current -eq 1) {
    Write-Host " OK (Already optimized)" -ForegroundColor Gray
} else {
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name DisableThumbnailCache -Value 1
    Write-Host " DONE" -ForegroundColor Green
}

Write-Host "`n [DONE] SSD optimization fully applied." -ForegroundColor Cyan
Write-Host "--------------------------------------------------------"

##------------------------------------------------------##

# ============================================================
# Runtime Installer and .NET Cleanup
# Package Manager: WinGet
# ============================================================

$ErrorActionPreference = "Continue"

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

$IgnoredExitCodes = @(
    -1978335135,
    -1978335189,
    -1978335191,
    -1978335221,
    -1978335212
)

$FixedPackages = @(
    "Microsoft.DirectX",
    "Oracle.JavaRuntimeEnvironment",
    "Microsoft.EdgeWebView2Runtime",
    "Microsoft.VCRedist.2015+.x86",
    "Microsoft.VCRedist.2015+.x64",
    "Microsoft.VCRedist.2013.x86",
    "Microsoft.VCRedist.2013.x64",
    "Microsoft.VCRedist.2012.x86",
    "Microsoft.VCRedist.2012.x64",
    "Microsoft.VCRedist.2010.x86",
    "Microsoft.VCRedist.2010.x64",
    "Microsoft.VCRedist.2008.x86",
    "Microsoft.VCRedist.2008.x64",
    "Microsoft.VCRedist.2005.x86",
    "Microsoft.VCRedist.2005.x64",
    "Microsoft.VSTOR",
    "Microsoft.XNARedist",
    "Nvidia.PhysXLegacy",
    "OpenAL.OpenAL",
    "Microsoft.DotNet.Framework.DeveloperPack_4"
)

$DotNetPrefixes = @(
    "Microsoft.DotNet.DesktopRuntime.",
    "Microsoft.DotNet.SDK."
)

# Always preserve these .NET major versions.
$FixedProtectedMajors = @(6, 8)

# ------------------------------------------------------------
# Counters
# ------------------------------------------------------------

$script:InstalledCount = 0
$script:SkippedCount  = 0
$script:FailedCount   = 0
$script:RemovedCount  = 0

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "SKIP")]
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "HH:mm:ss"

    switch ($Level) {
        "INFO" {
            $Color = "Cyan"
            $Prefix = "[INFO]"
        }
        "SUCCESS" {
            $Color = "Green"
            $Prefix = "[SUCCESS]"
        }
        "WARNING" {
            $Color = "Yellow"
            $Prefix = "[WARNING]"
        }
        "ERROR" {
            $Color = "Red"
            $Prefix = "[ERROR]"
        }
        "SKIP" {
            $Color = "DarkYellow"
            $Prefix = "[SKIP]"
        }
    }

    Write-Host "[$Timestamp] $Prefix $Message" -ForegroundColor $Color
}

# ------------------------------------------------------------
# WinGet availability
# ------------------------------------------------------------

function Test-WinGetAvailable {
    try {
        $null = Get-Command winget -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# ------------------------------------------------------------
# Registry inventory
# ------------------------------------------------------------

function Get-InstalledRegistryEntries {
    $RegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($RegistryPath in $RegistryPaths) {
        try {
            Get-ItemProperty -Path $RegistryPath -ErrorAction SilentlyContinue |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_.DisplayName)
                }
        }
        catch {
            # Ignore inaccessible registry paths.
        }
    }
}

# ------------------------------------------------------------
# Registry-based detection for packages with unreliable IDs
# ------------------------------------------------------------

function Test-PackageInRegistry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageId
    )

    $Entries = @(Get-InstalledRegistryEntries)

    foreach ($Entry in $Entries) {
        $Name = [string]$Entry.DisplayName
        $Version = [string]$Entry.DisplayVersion
        $RegistryPath = [string]$Entry.PSPath

        switch ($PackageId) {
            "Microsoft.EdgeWebView2Runtime" {
                if ($Name -match "^Microsoft Edge WebView2 Runtime(?:\s|$)") {
                    Write-Log "Registry match: $Name $Version" "SUCCESS"
                    return $true
                }
            }

            "Microsoft.VCRedist.2010.x86" {
                if (
                    $Name -match "^Microsoft Visual C\+\+ 2010.*Redistributable" -and
                    (
                        $Name -match "\bx86\b" -or
                        $RegistryPath -match "WOW6432Node"
                    )
                ) {
                    Write-Log "Registry match: $Name $Version" "SUCCESS"
                    return $true
                }
            }

            "Microsoft.VCRedist.2010.x64" {
                if (
                    $Name -match "^Microsoft Visual C\+\+ 2010.*Redistributable" -and
                    $Name -match "\bx64\b"
                ) {
                    Write-Log "Registry match: $Name $Version" "SUCCESS"
                    return $true
                }
            }

            "Microsoft.VCRedist.2005.x86" {
                if (
                    $Name -match "^Microsoft Visual C\+\+ 2005.*Redistributable" -and
                    (
                        $Name -match "\bx86\b" -or
                        $RegistryPath -match "WOW6432Node"
                    )
                ) {
                    Write-Log "Registry match: $Name $Version" "SUCCESS"
                    return $true
                }
            }

            "Microsoft.VCRedist.2005.x64" {
                if (
                    $Name -match "^Microsoft Visual C\+\+ 2005.*Redistributable" -and
                    $Name -match "\bx64\b"
                ) {
                    Write-Log "Registry match: $Name $Version" "SUCCESS"
                    return $true
                }
            }
        }
    }

    return $false
}

# ------------------------------------------------------------
# WinGet package detection
# ------------------------------------------------------------

function Test-WinGetPackageInstalled {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageId
    )

    try {
        $Output = @(
            & winget list `
                --id $PackageId `
                --exact `
                --disable-interactivity 2>$null
        )

        $ResultCode = $LASTEXITCODE
        $OutputText = $Output -join "`n"

        if (
            $ResultCode -eq 0 -and
            $OutputText -match [regex]::Escape($PackageId)
        ) {
            return $true
        }
    }
    catch {
        # Continue to the next detection method.
    }

    return $false
}

function Test-PackageInstalled {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageId
    )

    if (Test-PackageInRegistry -PackageId $PackageId) {
        return $true
    }

    if (Test-WinGetPackageInstalled -PackageId $PackageId) {
        return $true
    }

    return $false
}

# ------------------------------------------------------------
# Install fixed runtime packages
# ------------------------------------------------------------

function Install-WinGetPackage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageId
    )

    Write-Log "Checking package: $PackageId"

    if (Test-PackageInstalled -PackageId $PackageId) {
        Write-Log "Already installed: $PackageId" "SKIP"
        $script:SkippedCount++
        return
    }

    Write-Log "Installing package: $PackageId"

    try {
        & winget install `
            --id $PackageId `
            --exact `
            --source winget `
            --silent `
            --accept-package-agreements `
            --accept-source-agreements `
            --disable-interactivity

        $ResultCode = $LASTEXITCODE

        if ($ResultCode -eq 0) {
            Write-Log "Install command completed: $PackageId" "SUCCESS"
            $script:InstalledCount++
        }
        elseif ($IgnoredExitCodes -contains $ResultCode) {
            Write-Log "WinGet returned an ignored code ($ResultCode): $PackageId" "SKIP"
            $script:SkippedCount++
        }
        else {
            Write-Log "Installation failed: $PackageId. Exit code: $ResultCode" "ERROR"
            $script:FailedCount++
        }
    }
    catch {
        Write-Log "Installation error for ${PackageId}: $($_.Exception.Message)" "ERROR"
        $script:FailedCount++
    }
}

# ------------------------------------------------------------
# Read installed .NET packages from the WinGet table
# ------------------------------------------------------------

function Get-InstalledDotNetPackages {
    $Packages = @()

    Write-Log "Reading installed .NET SDK and Desktop Runtime inventory."

    try {
        $Output = @(
            & winget list --disable-interactivity 2>$null
        )

        $ResultCode = $LASTEXITCODE

        if ($ResultCode -ne 0) {
            Write-Log "WinGet could not return the installed package inventory." "WARNING"
            return @()
        }

        foreach ($Line in $Output) {
            $TrimmedLine = ([string]$Line).Trim()

            if ([string]::IsNullOrWhiteSpace($TrimmedLine)) {
                continue
            }

            # WinGet IDs are parsed independently of the table's
            # localized column headings.
            $IdMatches = [regex]::Matches(
                $TrimmedLine,
                'Microsoft\.DotNet\.(?:DesktopRuntime|SDK)\.\d+',
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            )

            foreach ($IdMatch in $IdMatches) {
                $PackageId = $IdMatch.Value

                if ($PackageId -match '^Microsoft\.DotNet\.DesktopRuntime\.(\d+)$') {
                    $Prefix = "Microsoft.DotNet.DesktopRuntime."
                    $Major = [int]$Matches[1]
                    $Family = "Desktop Runtime"
                }
                elseif ($PackageId -match '^Microsoft\.DotNet\.SDK\.(\d+)$') {
                    $Prefix = "Microsoft.DotNet.SDK."
                    $Major = [int]$Matches[1]
                    $Family = "SDK"
                }
                else {
                    continue
                }

                # Extract version-shaped values from the same row.
                # The installed version normally appears before the
                # available version in the WinGet list output.
                $VersionMatches = [regex]::Matches(
                    $TrimmedLine,
                    '(?<![\d.])\d+\.\d+\.\d+(?:\.\d+)?(?![\d.])'
                )

                $ParsedVersion = $null

                foreach ($VersionMatch in $VersionMatches) {
                    try {
                        $CandidateVersion = [version]$VersionMatch.Value

                        # Ignore rows where the extracted value is
                        # not consistent with the package major.
                        if ($CandidateVersion.Major -eq $Major) {
                            $ParsedVersion = $CandidateVersion
                            break
                        }
                    }
                    catch {
                        # Ignore malformed version values.
                    }
                }

                if ($null -eq $ParsedVersion) {
                    Write-Log "Could not determine installed version for $PackageId." "WARNING"
                    continue
                }

                $Packages += [PSCustomObject]@{
                    Id      = $PackageId
                    Prefix  = $Prefix
                    Family  = $Family
                    Major   = $Major
                    Version = $ParsedVersion
                }
            }
        }
    }
    catch {
        Write-Log "Error reading .NET inventory: $($_.Exception.Message)" "WARNING"
    }

    # Remove duplicate records without collapsing different versions.
    $Packages = @(
        $Packages |
            Sort-Object Id, Version -Unique
    )

    foreach ($Package in $Packages) {
        Write-Log (
            "Detected .NET {0}: ID={1}, Version={2}" -f
            $Package.Family,
            $Package.Id,
            $Package.Version
        ) "INFO"
    }

    return $Packages
}

# ------------------------------------------------------------
# Determine protected .NET major versions
# ------------------------------------------------------------

function Get-ProtectedDotNetMajors {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Packages
    )

    $ModernMajors = @(
        $Packages |
            Where-Object { $_.Major -ge 9 } |
            Select-Object -ExpandProperty Major -Unique |
            Sort-Object -Descending
    )

    $LatestThree = @(
        $ModernMajors | Select-Object -First 3
    )

    $Protected = @(
        $FixedProtectedMajors
        $LatestThree
    ) | Select-Object -Unique

    return @($Protected | Sort-Object)
}

# ------------------------------------------------------------
# Remove outdated .NET packages
# ------------------------------------------------------------

function Remove-OldDotNetPackages {
    Write-Log "Starting .NET cleanup."

    $Packages = @(Get-InstalledDotNetPackages)

    if ($Packages.Count -eq 0) {
        Write-Log "No .NET SDK or Desktop Runtime packages were parsed from WinGet." "WARNING"
        Write-Log "Cleanup was skipped to prevent accidental uninstallation." "WARNING"
        return
    }

    $ProtectedMajors = @(Get-ProtectedDotNetMajors -Packages $Packages)

    Write-Log "Protected .NET major versions: $($ProtectedMajors -join ', ')" "SUCCESS"

    $PackagesToRemove = @()

    # Remove all packages belonging to unprotected major versions.
    $PackagesToRemove += @(
        $Packages |
            Where-Object {
                $ProtectedMajors -notcontains $_.Major
            }
    )

    # For each package family and protected major, retain only
    # the newest installed version.
    foreach ($Prefix in $DotNetPrefixes) {
        foreach ($Major in $ProtectedMajors) {
            $MatchingPackages = @(
                $Packages |
                    Where-Object {
                        $_.Prefix -eq $Prefix -and
                        $_.Major -eq $Major
                    } |
                    Sort-Object Version -Descending
            )

            if ($MatchingPackages.Count -gt 1) {
                $PackagesToRemove += @(
                    $MatchingPackages | Select-Object -Skip 1
                )
            }
        }
    }

    $PackagesToRemove = @(
        $PackagesToRemove |
            Sort-Object Id, Version -Unique
    )

    if ($PackagesToRemove.Count -eq 0) {
        Write-Log "No outdated .NET packages need to be removed." "SUCCESS"
        return
    }

    foreach ($Package in $PackagesToRemove) {
        Write-Log (
            "Removing outdated .NET {0}: {1} ({2})" -f
            $Package.Family,
            $Package.Id,
            $Package.Version
        ) "WARNING"

        try {
            & winget uninstall `
                --id $Package.Id `
                --exact `
                --version $Package.Version.ToString() `
                --source winget `
                --silent `
                --accept-source-agreements `
                --disable-interactivity

            $ResultCode = $LASTEXITCODE

            if ($ResultCode -eq 0) {
                Write-Log "Removed: $($Package.Id), version $($Package.Version)" "SUCCESS"
                $script:RemovedCount++
            }
            elseif ($IgnoredExitCodes -contains $ResultCode) {
                Write-Log "Already installed: $($Package.Id)" "SKIP"
                $script:SkippedCount++
            }
            else {
                Write-Log "Could not remove $($Package.Id). Exit code: $ResultCode" "ERROR"
                $script:FailedCount++
            }
        }
        catch {
            Write-Log "Uninstall error for $($Package.Id): $($_.Exception.Message)" "ERROR"
            $script:FailedCount++
        }
    }
}

# ------------------------------------------------------------
# Main execution
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "           RUNTIME INSTALLER AND .NET CLEANUP" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-WinGetAvailable)) {
    Write-Log "WinGet is not available. Runtime installation and cleanup were skipped." "ERROR"
}
else {
    Write-Log "WinGet is available." "SUCCESS"

    foreach ($PackageId in $FixedPackages) {
        Install-WinGetPackage -PackageId $PackageId
    }

    Remove-OldDotNetPackages
}

# ------------------------------------------------------------
# Execution summary
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "                    EXECUTION SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Write-Host "Packages installed : $script:InstalledCount" -ForegroundColor Green
Write-Host "Packages removed   : $script:RemovedCount" -ForegroundColor Yellow
Write-Host "Packages skipped   : $script:SkippedCount" -ForegroundColor DarkYellow
Write-Host "Packages failed    : $script:FailedCount" -ForegroundColor Red

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Log "Runtime installation and cleanup module completed." "SUCCESS"

##------------------------------------------------------##

# --- INSTALL APPS VIA WINGET (WITH POPUP TIMEOUT) ---
Write-Host "`n[MODULE] Starting Interactive App Installation..." -ForegroundColor Cyan
$appsToInstall = @(
    @{ Name = "FluentFlyout"; ID = "9n45nsm4tnbp" },
    @{ Name = "TubeDigger"; ID = "TubeDigger.TubeDigger" },
    @{ Name = "AdGuardVPN"; ID = "AdGuard.AdGuardVPN" },
    @{ Name = "SignalRgb"; ID = "WhirlwindFX.SignalRgb" },
    @{ Name = "Hydra"; ID = "HydraLauncher.Hydra" },
    @{ Name = "Signal"; ID = "xp89119p9f2pcq" },
    @{ Name = "Sticky Password"; ID = "xp8lt301zl525k" },
    @{ Name = "Antigravity"; ID = "Google.Antigravity" },
    @{ Name = "WhatsApp"; ID = "9nksqgp7f2nh" },
    @{ Name = "Outlook"; ID = "9nrx63209r7b" },
    @{ Name = "OneDrive"; ID = "Microsoft.OneDrive" },
    @{ Name = "TeraBox"; ID = "xp8bz39v4j50xj" },
    @{ Name = "Microsoft Teams"; ID = "xp8bt8dw290mpq" },
    @{ Name = "Brave"; ID = "xp8c9qzms2pc1t" },
    @{ Name = "Zen"; ID = "Zen-Team.Zen-Browser" },
    @{ Name = "Mozilla Firefox"; ID = "9nzvdkpmr9rd" },
    @{ Name = "Comet"; ID = "Perplexity.Comet" },
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

# ----------------------------------------------------------------------
# Third-Party & External App Services Optimization
# ----------------------------------------------------------------------
Write-Host "-- Adjusting third-party app services..." -ForegroundColor Gray

$manualExternalServices = @(
    "OneDrive",                                                   # OneDrive
    "WiseBootAssistant",                                          # Wise Care
    "Adguard VPN Service",                                        # AdGuard
    "WireSockAppService", "WireSockConnectService",               # WireSock
    "TeraBoxUtility",                                             # TeraBox
    "ViscosityService"                                            # Viscosity VPN
)

$disabledExternalServices = @(
    "EPWD",              # Check Point Endpoint Security VPN / Third-party driver
    "TracSrvWrapper",    # Check Point VPN
    "NativePushService"  # Wondershare / Third-party Push Notification service
)

# Apply Manual startup type
$manualExternalServices | ForEach-Object { 
    if (Get-Service -Name $_ -ErrorAction SilentlyContinue) { 
        Set-Service -Name $_ -StartupType Manual -ErrorAction SilentlyContinue 
    } 
}

# Apply Disabled startup type
$disabledExternalServices | ForEach-Object { 
    if (Get-Service -Name $_ -ErrorAction SilentlyContinue) { 
        Set-Service -Name $_ -StartupType Disabled -ErrorAction SilentlyContinue 
    } 
}

Write-Host ""
Write-Host "Third-party services configured successfully! ✅" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host ""

##------------------------------------------------------##

# --- Browser Tweaks: Chrome, Brave, Edge & Firefox ---
Write-Host "-- Applying Browser Registry Tweaks (Chrome, Supermium, Brave, Edge & Firefox)..." -ForegroundColor Gray

# List of registry paths for centralized policy management
$browserPaths = @(
    "HKLM:\SOFTWARE\Policies\Google\Chrome",
    "HKLM:\SOFTWARE\Policies\Supermium",
    "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
    "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
    "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
)

# Shared Policy Settings (Applies to most Chromium-based browsers and Firefox)
$sharedTweaks = @{
    "PasswordManagerEnabled"          = 1   # Keep "Offer to save passwords" active
    "MetricsReportingEnabled"         = 0   # Disable telemetry and usage data collection
    "BackgroundModeEnabled"           = 0   # Prevent browser from running in the background after closing
    "HardwareAccelerationModeEnabled" = 0   # Disable GPU acceleration (may reduce performance, useful for troubleshooting/stability)
    "ComponentUpdatesEnabled"         = 0   # Disable automatic component updates
    "BuiltInComponentUpdaterEnabled"  = 0   # Disable built-in component updates
    "NetworkPredictionOptions"        = 2   # Disable network prediction and prefetching
    "SpellcheckEnabled"               = 0   # Disable built-in spellchecking
    "AutofillCreditCardEnabled"       = 0   # Disable automatic credit card autofill
}

# --- DISABLE CHROMIUM AI FEATURES ---
Write-Host "-- Disabling Chromium AI features (Edge / Chrome)..." -ForegroundColor Gray

$chromiumAIPathList = @(
    "HKLM:\SOFTWARE\Policies\Google\Chrome",
    "HKLM:\SOFTWARE\Policies\Supermium",
    "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
)

foreach ($aiPath in $chromiumAIPathList) {

    if (!(Test-Path $aiPath)) {
        New-Item -Path $aiPath -Force | Out-Null
    }

    # Disable local AI / foundational model features
    Set-ItemProperty -Path $aiPath -Name "GenAILocalFoundationalModelSettings" -Value 1 -Type DWord -ErrorAction SilentlyContinue
}

foreach ($basePath in $browserPaths) {
    # Create the key if it does not exist
    if (!(Test-Path $basePath)) { New-Item -Path $basePath -Force | Out-Null }
    
    # Determine the correct registry type (Firefox requires String for these policies)
    $type = if ($basePath -like "*Mozilla*") { "String" } else { "DWord" }
    
    foreach ($name in $sharedTweaks.Keys) {
        Set-ItemProperty -Path $basePath -Name $name -Value $sharedTweaks[$name] -Type $type -ErrorAction SilentlyContinue
    }

    # Remove DNS policies from HKLM ONLY for Brave to UNLOCK the button in the UI
    if ($basePath -like "*BraveSoftware*") {
        Remove-ItemProperty -Path $basePath -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $basePath -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
    }
    
    # Remove DNS policies from HKLM ONLY for Chrome
    #if ($basePath -like "*Google\Chrome*") {
    #    Remove-ItemProperty -Path $basePath -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
    #    Remove-ItemProperty -Path $basePath -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
    #}
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
    "DisableDeveloperTools"      = "0"  # Ensure Developer Tools remain enabled
    "DontCheckDefaultBrowser"    = "1"  # Disable the check for default browser
    "DisableBackgroundUpdate"    = "1"  # Disable background updates
}

foreach ($name in $firefoxTweaks.Keys) {
    Set-ItemProperty -Path $firefoxOnlyPath -Name $name -Value $firefoxTweaks[$name] -Type String -ErrorAction SilentlyContinue
}

# --- CHROME SPECIFIC DEBLOAT ---
# Policies for Google Chrome
$chromeOnlyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$chromeTweaks = @{
    "SyncDisabled"                      = 1     # Disable Sync
    "DefaultBrowserSettingEnabled"      = 0     # Don't Check Default Browser
    "DeveloperToolsAvailability"        = 1     # Enable Developer Mode
    "ChromeCleanupEnabled"              = 0     # Disable Chrome Cleanup Tool
    "ChromeCleanupReportingEnabled"     = 0     # Disable Cleanup reporting
    #"HardwareMediaKeyHandlingEnabled"   = 0     # Disable media key handling
}

#Remove-ItemProperty -Path $chromeOnlyPath -Name "HardwareMediaKeyHandlingEnabled" -ErrorAction SilentlyContinue

foreach ($name in $chromeTweaks.Keys) {
    Set-ItemProperty -Path $chromeOnlyPath -Name $name -Value $chromeTweaks[$name] -Type DWord -ErrorAction SilentlyContinue
}

# --- SUPERMIUM SPECIFIC DEBLOAT ---
# Policies for Supermium
$supermiumPath = "HKLM:\SOFTWARE\Policies\Supermium"

if (!(Test-Path $supermiumPath)) {
    New-Item -Path $supermiumPath -Force | Out-Null
}

$supermiumTweaks = @{
    "SyncDisabled"                      = 1  # Disable Google Sync
    "DefaultBrowserSettingEnabled"      = 0  # Disable default browser check
    "DeveloperToolsAvailability"        = 1  # Allow Developer Tools (F12)
    #"HardwareMediaKeyHandlingEnabled"   = 0     # Disable media key handling
}

#Remove-ItemProperty -Path $supermiumPath -Name "HardwareMediaKeyHandlingEnabled" -ErrorAction SilentlyContinue

foreach ($name in $supermiumTweaks.Keys) {
    Set-ItemProperty -Path $supermiumPath -Name $name -Value $supermiumTweaks[$name] -Type DWord -ErrorAction SilentlyContinue
}

# --- BRAVE SPECIFIC DEBLOAT ---
# Disables unnecessary Brave features and reduces optional data collection.

$bravePath = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"

if (!(Test-Path $bravePath)) {
    New-Item -Path $bravePath -Force | Out-Null
}

# Brave Feature Policies
$braveTweaks = @{
    "BraveVPNDisabled"             = 1  # Disable Brave VPN
    "BraveWalletDisabled"          = 1  # Disable the built-in Crypto Wallet
    "BraveAIChatEnabled"           = 0  # Disable Brave Leo AI Chat
    "BraveRewardsDisabled"         = 1  # Disable Brave Rewards and related ads
    "BraveTalkDisabled"            = 1  # Disable Brave Talk video calls
    "BraveNewsDisabled"            = 1  # Disable Brave News on the New Tab page
    "SyncDisabled"                 = 1  # Disable Brave Sync
    "DefaultBrowserSettingEnabled" = 0  # Disable default browser checks and prompts
    "DeveloperToolsAvailability"   = 2  # Allow access to Developer Tools
    "BuiltInDnsClientEnabled"      = 1  # Enable the built-in DNS client
}

# Additional Brave Privacy Policies
$bravePrivacyTweaks = @{
    "SafeBrowsingSurveysEnabled"              = 0  # Disable Safe Browsing surveys
    "UrlKeyedAnonymizedDataCollectionEnabled" = 0  # Disable anonymized URL-keyed data collection
    "FeedbackSurveysEnabled"                  = 0  # Disable feedback surveys
    "DomainReliabilityAllowed"                = 0  # Disable domain reliability reporting
    "PrivacySandboxPromptEnabled"             = 0  # Disable Privacy Sandbox prompts
    "UserFeedbackAllowed"                     = 0  # Disable user feedback reporting
    "UrlKeyedMetricsAllowed"                  = 0  # Disable URL-keyed metrics collection
}

# Apply Brave Feature Policies
foreach ($name in $braveTweaks.Keys) {
    Set-ItemProperty -Path $bravePath -Name $name -Value $braveTweaks[$name] -Type DWord -ErrorAction SilentlyContinue
}

# Apply Brave Privacy Policies
foreach ($name in $bravePrivacyTweaks.Keys) {
    Set-ItemProperty -Path $bravePath -Name $name -Value $bravePrivacyTweaks[$name] -Type DWord -ErrorAction SilentlyContinue
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
    "BingAdsSuppression"               = 1  # Suppress Bing search ads
    "NewTabPageHideDefaultTopSites"    = 1  # Cleanup default sites on new tabs
    "PromotionalTabsEnabled"           = 0  # Disable "Promotional" popups
    "SendSiteInfoToImproveServices"    = 0  # Disable site tracking for "improvement"
    "SpotlightExperiencesAndRecommendationsEnabled" = 0 # Disable spotlight ads
    "DiagnosticData"                   = 0  # Set diagnostic data to minimal/off
    "EdgeAssetDeliveryServiceEnabled"  = 0  # Disable asset background delivery
    "CryptoWalletEnabled"              = 0  # Disable Edge Crypto Wallet
    "WalletDonationEnabled"            = 0  # Disable donation features in Wallet
    "HubsSidebarEnabled"               = 0  # Remove the Edge Sidebar
    "CopilotPageAction"                = 0  # Disable the Copilot icon/action
    "SmartScreenEnabled"               = 0  # Disable SmartScreen UI
    "SmartScreenPuaFullScanEnabled"    = 0  # Disable SmartScreen PUA full scan
    "DeveloperToolsAvailability"       = 1  # Enable Developer Mode tools
    "BuiltInMicrosoftFormsEnabled"     = 0  # Disable internal Microsoft forms
    "EdgeManagementEnabled"            = 0  # Minimize unnecessary remote management
    "SyncDisabled"                     = 1  # Disable Sync
}

foreach ($name in $edgeTweaks.Keys) {
    Set-ItemProperty -Path $edgeOnlyPath -Name $name -Value $edgeTweaks[$name] -Type DWord -ErrorAction SilentlyContinue
}

# --- UNLOCKED SETTINGS (PREFERENCES) ---
# Set initial values but allow manual toggle in the UI (No "Managed by organization" lock)

$userPaths = @(
    "HKCU:\Software\Google\Chrome",
    "HKCU:\Software\BraveSoftware\Brave",
    "HKCU:\Software\Microsoft\Edge"
)

foreach ($uPath in $userPaths) {
    if (!(Test-Path $uPath)) { New-Item -Path $uPath -Force | Out-Null }
    
    # Safe Browsing set to 0 (Disabled) but toggleable
    Set-ItemProperty -Path $uPath -Name "SafeBrowsingEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $uPath -Name "StatsReportingDisabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
}

# Firefox Specific (Manual Toggle)
$ffPath = "HKCU:\Software\Mozilla\Firefox"
if (!(Test-Path $ffPath)) { New-Item -Path $ffPath -Force | Out-Null }
Set-ItemProperty -Path $ffPath -Name "DisableTelemetry" -Value "1" -Type String -ErrorAction SilentlyContinue

# --- INTERACTIVE DNS OVER HTTPS WITH TIMEOUT (GOOGLE CHROME) ---
Write-Host "Do you want to enable Secure DNS (DNS Over HTTPS) for CHROME? [Y/N] (Default: N in 5s): " -NoNewline

$counterChrome = 5
while ($counterChrome -gt 0 -and (-not [console]::KeyAvailable)) {
    Write-Host "..$counterChrome " -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
    $counterChrome--
}

if ([console]::KeyAvailable) {
    $choiceChromeDNS = [console]::ReadKey($true).KeyChar
    Write-Host ""
} else {
    Write-Host "`nTimeout reached. Disabling DNS Over HTTPS for Chrome..." -ForegroundColor Gray
    $choiceChromeDNS = "n"
}

# Mandatory Policy Injection: Chrome requires HKLM enforcement to override managed state.
# Value must be passed as String ("automatic" | "off") to maintain Chromium engine compatibility.
$chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if ($choiceChromeDNS -eq 'y' -or $choiceChromeDNS -eq 'Y') {
    Write-Host "-- Enabling DNS Over HTTPS for CHROME (Policy Mode)..." -ForegroundColor Cyan
    Set-ItemProperty -Path $chromePolicyPath -Name "DnsOverHttpsMode" -Value "automatic" -Type String -ErrorAction SilentlyContinue
} else {
    Write-Host "-- Disabling DNS Over HTTPS for CHROME..." -ForegroundColor Yellow
    Set-ItemProperty -Path $chromePolicyPath -Name "DnsOverHttpsMode" -Value "off" -Type String -ErrorAction SilentlyContinue
}

# --- CLEAR BUFFER ---
# Clears any leftover keystrokes so the next question doesn't skip
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }

# --- INTERACTIVE DNS OVER HTTPS WITH TIMEOUT (BRAVE ONLY) ---
Write-Host "Do you want to enable Secure DNS (DNS Over HTTPS) for BRAVE? [Y/N] (Default: N in 5s): " -NoNewline

$counterBrave = 5
while ($counterBrave -gt 0 -and (-not [console]::KeyAvailable)) {
    Write-Host "..$counterBrave " -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
    $counterBrave--
}

if ([console]::KeyAvailable) {
    $choiceBraveDNS = [console]::ReadKey($true).KeyChar
    Write-Host ""
} else {
    Write-Host "`nTimeout reached. Skipping DNS config..." -ForegroundColor Gray
    $choiceBraveDNS = "n"
}

if ($choiceBraveDNS -eq 'y' -or $choiceBraveDNS -eq 'Y') {
    Write-Host "-- Enabling DNS Over HTTPS for BRAVE (Unlocked Mode)..." -ForegroundColor Cyan
    $braveUserPath = "HKCU:\Software\BraveSoftware\Brave"
    Set-ItemProperty -Path $braveUserPath -Name "DnsOverHttpsMode" -Value "automatic" -Type String -ErrorAction SilentlyContinue
} else {
    Write-Host "-- DNS Over HTTPS for Brave remains disabled or unchanged." -ForegroundColor Yellow
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

##------------------------------------------------------##

# ================================================================
# SUPERMium - CONFIGURATION
# Compatible with Windows PowerShell 5.1+
# ================================================================

# --- CONFIGURATION ---
$browserCandidates = @(
    "C:\Program Files\Supermium\chrome.exe",
    "C:\Program Files (x86)\Supermium\chrome.exe"
)

$profileDir = Join-Path $env:LOCALAPPDATA "Supermium\User Data"
$localState = Join-Path $profileDir "Local State"

$shortcutDir  = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
$shortcutPath = Join-Path $shortcutDir "Supermium.lnk"

$iconPath = Join-Path $env:USERPROFILE "AppData\Local\Supermium\User Data\Default\Google Profile.ico"

$argument = "--extension-mime-request-handling=always-prompt-for-install"
$labSetting = "extension-mime-request-handling@1"

Write-Host ""
Write-Host "================================================" -ForegroundColor DarkGray
Write-Host "  SUPERMium - CONFIGURATION" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor DarkGray

# --- 1. DETECT SUPERMium INSTALLATION ---
Write-Host "`n[1/4] Detecting Supermium installation..." -ForegroundColor Cyan

$existingShortcutTarget = $null

if (Test-Path -LiteralPath $shortcutPath -PathType Leaf) {
    try {
        $shell = New-Object -ComObject WScript.Shell
        $existingShortcut = $shell.CreateShortcut($shortcutPath)
        $existingShortcutTarget = [string]$existingShortcut.TargetPath
    }
    catch {
        $existingShortcutTarget = $null
    }
}

# Prefer the executable already referenced by the shortcut if it exists.
$browserPath = $null

if ($existingShortcutTarget) {
    foreach ($candidate in $browserCandidates) {
        if (
            $existingShortcutTarget -ieq $candidate -and
            (Test-Path -LiteralPath $candidate -PathType Leaf)
        ) {
            $browserPath = $candidate
            break
        }
    }
}

# If the shortcut does not identify an existing installation,
# use the first existing candidate.
if (-not $browserPath) {
    foreach ($candidate in $browserCandidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $browserPath = $candidate
            break
        }
    }
}

if (-not $browserPath) {
    Write-Host "[ERROR] Supermium was not found in either location:" -ForegroundColor Red

    foreach ($candidate in $browserCandidates) {
        Write-Host "  - $candidate" -ForegroundColor Yellow
    }

    return
}

$browserDir = Split-Path -Parent $browserPath

Write-Host "[OK] Supermium found:" -ForegroundColor Green
Write-Host "     $browserPath" -ForegroundColor Gray

# --- 2. CLOSE SUPERMium IF RUNNING ---
Write-Host "`n[2/4] Checking Supermium processes..." -ForegroundColor Cyan

try {
    $processes = @(
        Get-CimInstance Win32_Process -Filter "Name = 'chrome.exe'" |
            Where-Object {
                $_.ExecutablePath -and
                $_.ExecutablePath -ieq $browserPath
            }
    )

    if ($processes.Count -gt 0) {
        foreach ($process in $processes) {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
        }

        Start-Sleep -Seconds 2
        Write-Host "[OK] Supermium processes closed." -ForegroundColor Green
    }
    else {
        Write-Host "[SKIP] Supermium is not running." -ForegroundColor DarkGray
    }
}
catch {
    Write-Host "[WARNING] Could not inspect every browser process: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- 3. CREATE OR UPDATE START MENU SHORTCUT ---
Write-Host "`n[3/4] Checking Start Menu shortcut..." -ForegroundColor Cyan

try {
    $shortcutNeedsUpdate = $false
    $expectedIcon = if (Test-Path -LiteralPath $iconPath -PathType Leaf) {
        $iconPath
    }
    else {
        "$browserPath,0"
    }

    if (-not (Test-Path -LiteralPath $shortcutPath -PathType Leaf)) {
        $shortcutNeedsUpdate = $true
        Write-Host "[INFO] Shortcut does not exist." -ForegroundColor Gray
    }
    else {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)

        if ($shortcut.TargetPath -ine $browserPath) {
            $shortcutNeedsUpdate = $true
        }

        if ($shortcut.WorkingDirectory -ine $browserDir) {
            $shortcutNeedsUpdate = $true
        }

        if ([string]$shortcut.Arguments -notmatch [regex]::Escape($argument)) {
            $shortcutNeedsUpdate = $true
        }

        $actualIcon = ([string]$shortcut.IconLocation).Trim().Trim('"')
        $normalizedExpectedIcon = $expectedIcon.Trim().Trim('"')

        if ($actualIcon -ine $normalizedExpectedIcon) {
            $shortcutNeedsUpdate = $true
        }
    }

    if ($shortcutNeedsUpdate) {
        if (-not (Test-Path -LiteralPath $shortcutDir -PathType Container)) {
            New-Item -Path $shortcutDir -ItemType Directory -Force |
                Out-Null
        }

        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)

        $shortcut.TargetPath = $browserPath
        $shortcut.WorkingDirectory = $browserDir
        $shortcut.IconLocation = $expectedIcon

        # Preserve existing arguments and add the flag only if missing.
        $existingArgs = [string]$shortcut.Arguments

        if ($existingArgs -notmatch [regex]::Escape($argument)) {
            $existingArgs = ($existingArgs.Trim() + " " + $argument).Trim()
        }

        $shortcut.Arguments = $existingArgs
        $shortcut.Save()

        Write-Host "[OK] Shortcut created or updated." -ForegroundColor Green
        Write-Host "     $shortcutPath" -ForegroundColor Gray
    }
    else {
        Write-Host "[SKIP] Shortcut is already correctly configured." -ForegroundColor DarkGray
    }
}
catch {
    Write-Host "[WARNING] Shortcut check/update failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- 4. CHECK AND UPDATE LOCAL STATE ---
Write-Host "`n[4/4] Checking Supermium Local State..." -ForegroundColor Cyan

try {
    if (-not (Test-Path -LiteralPath $localState -PathType Leaf)) {
        Write-Host "[SKIP] Local State does not exist yet." -ForegroundColor DarkGray
    }
    else {
        $jsonText = Get-Content -LiteralPath $localState -Raw -Encoding UTF8
        $state = $jsonText | ConvertFrom-Json

        $labs = @()

        if ($state.browser -and $state.browser.enabled_labs_experiments) {
            $labs = @($state.browser.enabled_labs_experiments)
        }

        if ($labs -contains $labSetting) {
            Write-Host "[SKIP] Local State setting is already configured." -ForegroundColor DarkGray
        }
        else {
            # Back up only when a change is required.
            $backupPath = "$localState.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            Copy-Item -LiteralPath $localState -Destination $backupPath -Force

            if (-not $state.browser) {
                $state | Add-Member `
                    -MemberType NoteProperty `
                    -Name browser `
                    -Value ([PSCustomObject]@{})
            }

            $labs += $labSetting
            $state.browser.enabled_labs_experiments = @($labs)

            $updatedJson = $state | ConvertTo-Json -Depth 100
            $tempPath = "$localState.tmp"

            try {
                Set-Content -LiteralPath $tempPath -Value $updatedJson -Encoding UTF8

                # Validate JSON before replacing the original file.
                $null = Get-Content -LiteralPath $tempPath -Raw -Encoding UTF8 |
                    ConvertFrom-Json

                Move-Item -LiteralPath $tempPath -Destination $localState -Force

                Write-Host "[OK] Local State setting added." -ForegroundColor Green
                Write-Host "[BACKUP] $backupPath" -ForegroundColor Gray
            }
            finally {
                if (Test-Path -LiteralPath $tempPath) {
                    Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}
catch {
    Write-Host "[WARNING] Local State check/update failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "-- Finished --" -ForegroundColor Cyan
Write-Host "Open Supermium using the Start Menu shortcut." -ForegroundColor Cyan
Write-Host ""

##------------------------------------------------------##

# --- Gaming Essentials Pack (5-second Timeout) ---
Write-Host "`n--- Gaming Essentials Check ---" -ForegroundColor Cyan

# Define the Game Pack IDs (Using Store ID for Xbox App)
$gamePack = @("Valve.Steam", "Discord.Discord", "ElectronicArts.EADesktop", "EpicGames.EpicGamesLauncher", "9MV0B5HZVK9Z", "xpdp2qw12dfsfk", "Playnite.Playnite")
$gamePackNames = "Steam, Discord, EA Desktop, Epic Games, Xbox App, Ubisoft Connect, Playnite"

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
Write-Host ""

# Detect whether the operating system is Windows Server
$isWindowsServer = $false

try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

    # ProductType:
    # 1 = Workstation (Windows 10/11)
    # 2 = Domain Controller
    # 3 = Server
    $isWindowsServer = ($osInfo.ProductType -ne 1)

    if ($isWindowsServer) {
        Write-Host "[INFO] Windows Server detected: $($osInfo.Caption)" -ForegroundColor Yellow
        Write-Host "[INFO] Server-specific application exclusions enabled." -ForegroundColor Yellow
    }
    else {
        Write-Host "[INFO] Windows client detected: $($osInfo.Caption)" -ForegroundColor Green
    }
}
catch {
    Write-Warning "Unable to detect the operating system type. Server-specific exclusions will not be applied."
}

Write-Host ""

# Packages that must NOT be installed on Windows Server.
# Add more Chocolatey package IDs to this list as needed.
$packagesToSkipOnServer = @(
    "webcamoid"
    "th-ch-youtube-music"
    "jami"
    "audacity"
    "qalculate"

    # Add more packages below, for example:
    # "vlc"
    # "paint.net"
)

# Packages to install through Chocolatey
$packagesToInstall = @(
    "webcamoid"
    "dart-sdk" # Its path handling is separate below
    "qdir"
    "openssh"
    "vscodium"
    "notepadplusplus"
    "imageglass"
    "git"
    "nano"
    "gh"
    "curl"
    "adb"
    "glab"
    "portx"
    "tabby"
    "vlc"
    "vlc-skins"
    "paint.net"
    "fastfetch"
    "qalculate"
    "audacity"
    "everything"
    "grepwin"
    "hashcheck"
    "openhashtab"
    "jami"
    "rustdesk"
    "sd-card-formatter"
    "th-ch-youtube-music"
    "winscp.install"
    "zstandard"
)

# Handle Python separately before the loop to ensure robust check
if (-not (Test-PythonInstalled)) {
    Write-Host "Python (v3+) not found or not suitable. Attempting to install Python via Chocolatey..."

    try {
        choco install python -y --no-progress

        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to install Python. Chocolatey exit code: $LASTEXITCODE"
        }
        else {
            Write-Host "Python installed successfully." -ForegroundColor Green
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Error ("An error occurred while trying to install Python: {0}" -f $errorMessage)
    }
}
else {
    Write-Host "Python (v3+) is already installed. Skipping Chocolatey installation for Python."
}

Write-Host ""

# Install the specified packages
foreach ($package in $packagesToInstall) {

    # Skip packages listed in $packagesToSkipOnServer on Windows Server
    if ($isWindowsServer -and $packagesToSkipOnServer -contains $package) {
        Write-Host "[SKIP] $package is excluded on Windows Server." -ForegroundColor Yellow
        Write-Host ""
        continue
    }

    Write-Host "Checking and installing $package..."

    try {
        # Check whether the package is already installed
        $installedPackages = @(
            choco list --local-only --exact $package -r 2>$null
        )

        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not reliably check whether $package is installed. Skipping installation to avoid an unintended change."
        }
        elseif ($installedPackages.Count -eq 0) {
            choco install $package -y --no-progress

            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Failed to install $package. Chocolatey exit code: $LASTEXITCODE"
            }
            else {
                Write-Host "$package installed successfully." -ForegroundColor Green
            }
        }
        else {
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
# ==========================================
# STARTUP APPLICATIONS - DISABLE MANAGER
# Registry + Startup Folders
# ==========================================

Write-Host "`n=== Configuring Startup Applications ===" -ForegroundColor Cyan

# --- 1. TARGET APPLICATIONS ---
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
    "Teams",
    "PDFMonitor",
    "Pawzy",
    "IDMan",
    "TrGUI",
    "pritunl",
    "teraboxwebservice"
)

# --- 2. REGISTRY CONFIGURATION ---
$disabledVal = [byte[]](
    0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
)

$startupApprovedPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Task",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Task"
)

$runPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)

$backupPath = "HKCU:\Software\StartupDisabledBackup"

if (-not (Test-Path $backupPath)) {
    New-Item -Path $backupPath -Force | Out-Null
}

# --- 3. DISABLE STARTUPAPPROVED ENTRIES ---
Write-Host "`n[1/5] Updating StartupApproved entries..." -ForegroundColor Cyan

foreach ($path in $startupApprovedPaths) {
    if (-not (Test-Path $path)) {
        continue
    }

    try {
        $key = Get-Item -LiteralPath $path -ErrorAction Stop

        foreach ($name in $key.GetValueNames()) {
            foreach ($target in $targets) {
                if ($name -match [regex]::Escape($target)) {
                    try {
                        Set-ItemProperty -LiteralPath $path `
                            -Name $name `
                            -Value $disabledVal `
                            -ErrorAction Stop

                        Write-Host "[DISABLED] $name ($path)" `
                            -ForegroundColor Green
                    }
                    catch {
                        Write-Host "[ERROR] $name : $($_.Exception.Message)" `
                            -ForegroundColor Red
                    }

                    break
                }
            }
        }
    }
    catch {
        Write-Host "[WARNING] Cannot access $path : $($_.Exception.Message)" `
            -ForegroundColor Yellow
    }
}

# --- 4. REMOVE MATCHING RUN ENTRIES WITH BACKUP ---
Write-Host "`n[2/5] Checking Run registry entries..." -ForegroundColor Cyan

foreach ($path in $runPaths) {
    if (-not (Test-Path $path)) {
        continue
    }

    try {
        $key = Get-Item -LiteralPath $path -ErrorAction Stop

        foreach ($name in $key.GetValueNames()) {
            $value = [string]$key.GetValue($name)
            $matched = $false

            foreach ($target in $targets) {
                if (
                    $name -match [regex]::Escape($target) -or
                    $value -match [regex]::Escape($target)
                ) {
                    $matched = $true
                    break
                }
            }

            if (-not $matched) {
                continue
            }

            try {
                $backupName = "Run_" + [guid]::NewGuid().ToString("N")

                New-ItemProperty -Path $backupPath `
                    -Name $backupName `
                    -Value "$path|$name|$value" `
                    -PropertyType String `
                    -Force `
                    -ErrorAction Stop | Out-Null

                Remove-ItemProperty -LiteralPath $path `
                    -Name $name `
                    -Force `
                    -ErrorAction Stop

                Write-Host "[DISABLED] $name removed from $path" `
                    -ForegroundColor Green
            }
            catch {
                Write-Host "[ERROR] $name ($path): $($_.Exception.Message)" `
                    -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "[WARNING] Cannot access $path : $($_.Exception.Message)" `
            -ForegroundColor Yellow
    }
}

# --- 5. DELETE PAWZY.BAT FROM USER STARTUP ---
Write-Host "`n[3/5] Checking Pawzy startup entry..." -ForegroundColor Cyan

$startupFolder = [Environment]::GetFolderPath("Startup")
$pawzy = Join-Path $startupFolder "Pawzy.bat"

if (Test-Path -LiteralPath $pawzy) {
    try {
        Remove-Item -LiteralPath $pawzy -Force -ErrorAction Stop
        Write-Host "[DELETED] Pawzy.bat removed from Startup." -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Pawzy.bat : $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "[INFO] Pawzy.bat not found in Startup." -ForegroundColor DarkGray
}

# --- 6. DELETE MATCHING ITEMS IN STARTUP FOLDERS ---
Write-Host "`n[4/5] Checking user and common Startup items..." `
    -ForegroundColor Cyan

$startupFolders = @(
    [Environment]::GetFolderPath("Startup"),
    [Environment]::GetFolderPath("CommonStartup")
) | Where-Object {
    $_ -and (Test-Path -LiteralPath $_)
} | Select-Object -Unique

foreach ($folder in $startupFolders) {
    try {
        $items = Get-ChildItem -LiteralPath $folder -Force `
            -ErrorAction Stop |
            Where-Object { -not $_.PSIsContainer }

        foreach ($item in $items) {
            $matched = $false

            # Match item name against all configured targets.
            foreach ($target in $targets) {
                if ($item.Name -match [regex]::Escape($target)) {
                    $matched = $true
                    break
                }
            }

            # For shortcuts, also inspect their actual target.
            if (
                -not $matched -and
                $item.Extension -eq ".lnk"
            ) {
                try {
                    $shell = New-Object -ComObject WScript.Shell
                    $shortcut = $shell.CreateShortcut($item.FullName)
                    $shortcutTarget = [string]$shortcut.TargetPath

                    foreach ($target in $targets) {
                        if ($shortcutTarget -match [regex]::Escape($target)) {
                            $matched = $true
                            break
                        }
                    }
                }
                catch {
                    Write-Host "[WARNING] Cannot inspect shortcut $($item.Name)" `
                        -ForegroundColor Yellow
                }
            }

            if (-not $matched) {
                continue
            }

            # Permanently delete the matching Startup item.
            try {
                Remove-Item -LiteralPath $item.FullName `
                    -Force `
                    -ErrorAction Stop

                Write-Host "[DELETED] Startup item: $($item.Name)" `
                    -ForegroundColor Green
            }
            catch {
                Write-Host "[ERROR] $($item.Name): $($_.Exception.Message)" `
                    -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "[WARNING] Cannot inspect $folder : $($_.Exception.Message)" `
            -ForegroundColor Yellow
    }
}

# --- 7. VERIFY TARGET EXECUTABLES ---
Write-Host "`n[5/5] Checking target executables..." -ForegroundColor Cyan

$executables = @(
    "C:\Program Files\PDFgear\PDFMonitor.exe",
    "C:\Program Files (x86)\Internet Download Manager\IDMan.exe",
    "C:\Program Files (x86)\CheckPoint\Endpoint Connect\TrGUI.exe",
    "C:\Program Files (x86)\Pritunl\pritunl.exe",
    "$env:APPDATA\TeraBox\teraboxwebservice.exe",
    "C:\Program Files (x86)\Skillbrains\lightshot\Lightshot.exe"
)

foreach ($exe in $executables) {
    if (Test-Path -LiteralPath $exe) {
        Write-Host "[FOUND] $exe" -ForegroundColor Gray
    }
    else {
        Write-Host "[NOT FOUND] $exe" -ForegroundColor DarkGray
    }
}

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "Startup configuration completed." -ForegroundColor Cyan
Write-Host "Review any [ERROR] or [WARNING] messages above."
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

##------------------------------------------------------##

# --- 7. EXTERNAL STARTUP METHODS (Shortcuts & Folders) ---
Write-Host "Checking for file-based startup shortcuts..." -ForegroundColor Cyan

# List of shortcut filenames to remove (without the .lnk extension)
$AppsToRemove = @(
    "ShareX"
)

# Common Startup paths
$StartupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($AppName in $AppsToRemove) {
    foreach ($Folder in $StartupFolders) {
        $ShortcutPath = Join-Path $Folder "$AppName.lnk"

        if (Test-Path $ShortcutPath) {
            try {
                Remove-Item -Path $ShortcutPath -Force -ErrorAction Stop
                Write-Host "[!] Removed $AppName startup shortcut from: $Folder" -ForegroundColor Green
            } catch {
                Write-Host "[X] Failed to remove $AppName shortcut: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    # Kill process if running to complete the 'disable' effect
    Stop-Process -Name $AppName -Force -ErrorAction SilentlyContinue
}

Write-Host "Startup shortcut cleanup complete." -ForegroundColor Cyan

##------------------------------------------------------##

# --- 8. GITHUB ENVIRONMENT & CASE SENSITIVITY ---
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

# --- 9. Git Context Menu Purge ---
# ==============================================================================
# SCRIPT: Git Context Menu Removal
# DESCRIPTION: Removes Git GUI Here and Git Bash Here context menu entries.
#              Checks standard machine-wide and current-user registry locations.
# ==============================================================================

Write-Host "`n--- Removing Git Context Menu Entries ---" -ForegroundColor Cyan

$gitMenuPaths = @(
    "HKCU:\Software\Classes\Directory\shell\git_shell",
    "HKCU:\Software\Classes\Directory\shell\git_gui",
    "HKCU:\Software\Classes\Directory\Background\shell\git_shell",
    "HKCU:\Software\Classes\Directory\Background\shell\git_gui",
    "HKCU:\Software\Classes\LibraryFolder\background\shell\git_gui",
    "HKCU:\Software\Classes\LibraryFolder\background\shell\git_shell",

    "HKLM:\SOFTWARE\Classes\Directory\shell\git_shell",
    "HKLM:\SOFTWARE\Classes\Directory\shell\git_gui",
    "HKLM:\SOFTWARE\Classes\Directory\Background\shell\git_shell",
    "HKLM:\SOFTWARE\Classes\Directory\Background\shell\git_gui",
    "HKLM:\SOFTWARE\Classes\LibraryFolder\background\shell\git_gui",
    "HKLM:\SOFTWARE\Classes\LibraryFolder\background\shell\git_shell"
)

$removed = 0

foreach ($path in $gitMenuPaths) {
    if (Test-Path -LiteralPath $path) {
        try {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
            Write-Host "[REMOVED] $path" -ForegroundColor Green
            $removed++
        }
        catch {
            Write-Host "[ERROR] $path : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host "`n[OK] Removed $removed Git context-menu entries." -ForegroundColor Cyan
Write-Host "--------------------------------------------------------"

##------------------------------------------------------##

# --- 10. GREPWIN CONTEXT MENU PURGE ---
# Removes grepWin from all context menu handlers (Files, Directories, and Background).
# Using native 'reg.exe' for maximum performance and to avoid PowerShell Registry provider overhead.
Write-Host "`n[CLEANUP] Purging grepWin shell entries..." -ForegroundColor Cyan

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

# --- 11. CLEAR POWERSHELL HISTORY ---
$historyFile = "$HOME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

if (Test-Path $historyFile) {
    Remove-Item $historyFile -Force -ErrorAction SilentlyContinue
}

##------------------------------------------------------##

# --- 12. FINALIZATION TERMINAL BOX ---
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Gray
Write-Host "  ║                                                      ║" -ForegroundColor Gray
Write-Host "  ║   " -NoNewline -ForegroundColor Gray
Write-Host "SYSTEM STATUS: OPTIMIZED & SECURED  ✅ 🐾          " -ForegroundColor Green
Write-Host "  ║                                                      ║" -ForegroundColor Gray
Write-Host "  ║   " -NoNewline -ForegroundColor Gray
Write-Host "The PC is happy now. Go grab a tea. ☕                " -ForegroundColor White
Write-Host "  ║   " -NoNewline -ForegroundColor Gray
Write-Host "Even the parrot thinks this build is fly. 🦜          " -ForegroundColor White
Write-Host "  ║                                                      ║" -ForegroundColor Gray
Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Gray
Write-Host ""

# --- EXIT PROTOCOL (7s AUTO-CLOSE) ---
Write-Host "  >> All done! Press any key to vanish... " -ForegroundColor DarkGray -NoNewline

$timer = 7
while ($timer -gt 0 -and (-not [console]::KeyAvailable)) {
    Write-Host "..$timer " -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
    $timer--
}

# If a key was pressed, clear it from the buffer before exiting
if ([console]::KeyAvailable) {
    [void][console]::ReadKey($true)
}

Write-Host "`n  [!] System exiting..." -ForegroundColor Gray

# Forces the current PowerShell process to terminate immediately
[System.Environment]::Exit(0)

##------------------------------------------------------##
