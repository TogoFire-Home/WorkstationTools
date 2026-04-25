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
# 44. JUNKWARE PURGE: Interactive 5s skip-prompt to remove "Digital Parasites" (McAfee, Norton, AVG, Kaspersky) using official manufacturer removal tools.
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
Write-Host ""

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
    Microsoft License Management Tool
.DESCRIPTION
    Menu-driven script to manage Windows and Office (including Project/Visio) keys.
    Features a 5-second automatic timeout on the main menu.
#>

function Show-LicenseMenu {
    Write-Host "`n================================================" -ForegroundColor Cyan
    Write-Host "   MICROSOFT LICENSE MANAGEMENT TOOL            " -ForegroundColor White
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "1. Remove Windows Product Key"
    Write-Host "2. Install Windows Product Key"
    Write-Host "3. Remove Office / Project / Visio Keys"
    Write-Host "4. Skip / Continue Script"
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "Select an option (Auto-skip in 5s): " -NoNewline
}

function Remove-WindowsKey {
    Write-Host "`nCleaning Windows license state..." -ForegroundColor Yellow
    slmgr /cpky
    slmgr /upk
    slmgr /rilc
    Write-Host "Windows license cleared successfully! ✅" -ForegroundColor Green
}

function Install-WindowsKey {
    $key = Read-Host "`nEnter the Windows Product Key (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)"
    if ($key -match "([A-Z0-9]{5}-){4}[A-Z0-9]{5}") {
        Write-Host "Installing key..." -ForegroundColor Yellow
        slmgr /ipk $key
        slmgr /ato
    } else {
        Write-Host "Invalid Key Format!" -ForegroundColor Red
    }
}

function Remove-OfficeKeys {
    Write-Host "`nScanning for Office/Project/Visio keys..." -ForegroundColor Cyan
    $paths = @(
        "${env:ProgramFiles}\Microsoft Office\Office16\ospp.vbs",
        "${env:ProgramFiles(x86)}\Microsoft Office\Office16\ospp.vbs"
    )
    $osppPath = $null
    foreach ($path in $paths) { if (Test-Path $path) { $osppPath = $path; break } }

    if (-not $osppPath) {
        Write-Host "ERROR: Office path not found." -ForegroundColor Red
        return
    }

    $status = cscript //nologo "$osppPath" /dstatus
    $keys = $status | Select-String "Last 5 characters of installed product key:"

    if (-not $keys) {
        Write-Host "No Office keys found." -ForegroundColor Yellow
    } else {
        foreach ($keyLine in $keys) {
            $keyFragment = $keyLine.ToString().Split(":")[-1].Trim()
            Write-Host "Removing Key: $keyFragment..." -ForegroundColor Yellow
            cscript //nologo "$osppPath" /unpkey:$keyFragment | Out-Null
            Write-Host "Key $keyFragment removed! ✅" -ForegroundColor Green
        }
    }
}

# --- Main Menu Execution ---
$timeout = 5
$selection = $null

Show-LicenseMenu

while ($timeout -gt 0) {
    if ([console]::KeyAvailable) {
        $selection = [console]::ReadKey($true).KeyChar
        break
    }
    Write-Host "..$timeout" -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
    $timeout--
}

if ($null -eq $selection -or $timeout -eq 0) {
    Write-Host "`n`nTimeout reached. Proceeding to next tasks..." -ForegroundColor Yellow
} else {
    switch ($selection) {
        '1' { Remove-WindowsKey }
        '2' { Install-WindowsKey }
        '3' { Remove-OfficeKeys }
        '4' { Write-Host "`nSkipping to next tasks..." -ForegroundColor Gray }
        Default { Write-Host "`nInvalid selection. Continuing script..." -ForegroundColor Gray }
    }
}

# Reset colors and continue
[Console]::ResetColor()
Write-Host "`nProceeding to system optimizations...`n" -ForegroundColor Gray
Write-Host ""

# Clear buffer
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }

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

Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
Set-RegValueSafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0

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

# ============================================
# ADS / TRACKING
# ============================================

Write-Host "`n=== Ads / Tracking ==="

Set-RegValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
Set-RegValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" "TailoredExperiencesWithDiagnosticDataEnabled" 0

# ============================================
# BACKGROUND DATA
# ============================================

Write-Host "`n=== Background Data ==="

Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0
Set-RegValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0
Set-RegValueSafe "HKCU:\Software\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0

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

# 2. MAS
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

# Clear buffer
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }

##------------------------------------------------------##

# --- REMOVE WINDOWS AI: FEATURE BREAKDOWN ---
# [DisableRegKeys]          -> Turns off Copilot, Recall logging, and typing data harvesting.
# [DisableCopilotPolicies]  -> Hard-disables AI features via Group Policy (SecPol).
# [RemoveAppxPackages]     -> Uninstalls Modern AI apps (UWP) and AI Fabric services.
# [RemoveRecallFeature]     -> Disables the Windows "Recall" screenshot-based timeline.
# [HideAIComponents]        -> Hides the "AI Components" page from Windows Settings.
# [DisableRewrite]          -> Disables the "AI Rewrite" feature in Notepad.
# [RemoveRecallTasks]       -> Forcibly deletes scheduled tasks used by the Recall engine.

Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host "Launch RemoveWindowsAI (Safe Mode)? This will lobotomize system AI. [Y/N] (Auto-Skip in 5s): " -NoNewline -ForegroundColor Red

# 1. First, we ask the user (Wait 5s)
$counterAI = 5
while ($counterAI -gt 0 -and (-not [console]::KeyAvailable)) {
    Write-Host "..$counterAI " -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
    $counterAI--
}

if ([console]::KeyAvailable) {
    $choiceAI = [console]::ReadKey($true).KeyChar
    Write-Host ""
} else {
    Write-Host "`nAI components preserved. Skipping cleanup." -ForegroundColor DarkGray
    $choiceAI = "n"
}

# 2. If the user said YES, then we check for PowerShell version
if ($choiceAI -eq 'y' -or $choiceAI -eq 'Y') {
    
    $aiCommand = '& ([scriptblock]::Create((irm "https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1"))) -nonInteractive -Options DisableRegKeys,DisableCopilotPolicies,RemoveAppxPackages,RemoveRecallFeature,HideAIComponents,DisableRewrite,RemoveRecallTasks'

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        Write-Host "[!] PowerShell 7 detected. Relaunching in Windows PowerShell 5.1..." -ForegroundColor Yellow
        Start-Process powershell.exe -ArgumentList "-NoProfile", "-ExecutionPolicy Bypass", "-Command", $aiCommand -Wait
    } else {
        Write-Host "[🚀] Initializing RemoveWindowsAI (Safe Mode)..." -ForegroundColor Cyan
        Invoke-Expression $aiCommand
    }

    Write-Host "`n[✅] AI cleanup process completed successfully." -ForegroundColor Green
} else {
    Write-Host "-- Windows AI settings remained unchanged." -ForegroundColor Yellow
}

# Clear keyboard buffer
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }
Write-Host "--------------------------------------------------------" -ForegroundColor Gray

##------------------------------------------------------##

# --- INTERACTIVE MICROSOFT EDGE UNINSTALLATION ---
# Displays a yellow warning and waits for user confirmation (5-second timeout)
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
    $choiceEdge = "n"
}

if ($choiceEdge -eq 'y' -or $choiceEdge -eq 'Y') {
    Write-Host "-- Initializing Edge uninstallation..." -ForegroundColor Green

    # 1. Enable uninstallation flag in Registry to bypass system restrictions
    $regPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev"
    if (-not (Test-Path $regPath)) { 
        New-Item -Path $regPath -Force | Out-Null 
    }
    Set-ItemProperty -Path $regPath -Name "AllowUninstall" -Value 1 -Type DWord -ErrorAction SilentlyContinue

    # 2. Locate the official Microsoft Edge setup installer
    $edgeApps = Get-ChildItem "C:\Program Files (x86)\Microsoft\Edge\Application\*\Installer\setup.exe" -ErrorAction SilentlyContinue
    
    if ($edgeApps) {
        $installerPath = $edgeApps[0].FullName
        
        # Create a placeholder file to prevent Windows Update from re-registering the legacy Edge app
        $legacyAppPath = "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe"
        New-Item $legacyAppPath -Force -ErrorAction SilentlyContinue | Out-Null
        
        # Execute the uninstaller with force and profile deletion arguments
        Start-Process $installerPath -ArgumentList '--uninstall --system-level --force-uninstall --delete-profile' -Wait
        
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
}

Write-Host "--------------------------------------------------------"
Write-Host ""

# Clear buffer
while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }

##------------------------------------------------------##

Write-Host "--- SYSTEM PURGE: REMOVING JUNKWARE & DIGITAL PARASITES ---" -ForegroundColor Red -BackgroundColor Black

# --- SYSTEM PURGE MENU: ANTIVIRUS REMOVAL TOOLS ---
# This menu allows for the selective execution of official uninstallation tools.
# Includes a 5-second inactivity timeout that defaults to [Q]uit.

do {
    Write-Host "`n================================================" -ForegroundColor Gray
    Write-Host "   🛡️ JUNKWARE PURGE: CHOOSE YOUR TARGET" -ForegroundColor Red
    Write-Host "================================================" -ForegroundColor Gray
    Write-Host " [1] McAfee Removal (MCPR)"
    Write-Host " [2] Kaspersky Removal (kavremvr)"
    Write-Host " [3] Norton Removal (Exorcism Tool)"
    Write-Host " [4] AVG Removal (Clear-Cut)"
    Write-Host " [Q] Quit Menu"
    Write-Host "------------------------------------------------" -ForegroundColor Gray
    Write-Host "Select an option (Auto-Exit in 5s): " -NoNewline -ForegroundColor White

    # --- Timer Logic for Menu Selection ---
    $menuTimer = 5
    $menuChoice = $null

    while ($menuTimer -gt 0 -and (-not [console]::KeyAvailable)) {
        Write-Host "..$menuTimer " -NoNewline -ForegroundColor Gray
        Start-Sleep -Seconds 1
        $menuTimer--
    }

    if ([console]::KeyAvailable) {
        $menuChoice = [console]::ReadKey($true).KeyChar
        Write-Host "$menuChoice" -ForegroundColor Cyan
    } else {
        Write-Host "`n[TIMEOUT] No selection made. Exiting menu..." -ForegroundColor DarkGray
        $menuChoice = "q"
    }

    switch ($menuChoice) {
        "1" {
            # --- INTERACTIVE MCAFEE REMOVAL ---
            Write-Host "`nLaunch MCPR? McAfee is basically a virus you pay for. Kill it? [Y/N] (Auto-Skip in 5s): " -NoNewline -ForegroundColor Yellow
            $counterMcAfee = 5
            while ($counterMcAfee -gt 0 -and (-not [console]::KeyAvailable)) {
                Write-Host "..$counterMcAfee " -NoNewline -ForegroundColor Gray
                Start-Sleep -Seconds 1
                $counterMcAfee--
            }
            if ([console]::KeyAvailable) {
                $choiceMcAfee = [console]::ReadKey($true).KeyChar
                Write-Host ""
            } else {
                Write-Host "`nMercy granted. McAfee survived... for now." -ForegroundColor DarkGray
                $choiceMcAfee = "n"
            }
            if ($choiceMcAfee -eq 'y' -or $choiceMcAfee -eq 'Y') {
                Write-Host "-- Summoning McAfee Consumer Product Removal (MCPR)..." -ForegroundColor Cyan
                $mcAfeeUrl = "https://download.mcafee.com/molbin/iss-loc/SupportTools/MCPR/MCPR.exe"
                $mcAfeePath = "$env:TEMP\MCPR.exe"
                Invoke-WebRequest -Uri $mcAfeeUrl -OutFile $mcAfeePath
                Write-Host "-- FATALITY! Executing MCPR..." -ForegroundColor Green
                Start-Process $mcAfeePath
            }
        }

        "2" {
            # --- INTERACTIVE KASPERSKY REMOVAL ---
            Write-Host "`nSend Kaspersky to the gulag with 'kavremvr'? [Y/N] (Auto-Skip in 5s): " -NoNewline -ForegroundColor Yellow
            $counterKav = 5
            while ($counterKav -gt 0 -and (-not [console]::KeyAvailable)) {
                Write-Host "..$counterKav " -NoNewline -ForegroundColor Gray
                Start-Sleep -Seconds 1
                $counterKav--
            }
            if ([console]::KeyAvailable) {
                $choiceKav = [console]::ReadKey($true).KeyChar
                Write-Host ""
            } else {
                Write-Host "`nPeace treaty signed. Skipping Kaspersky." -ForegroundColor DarkGray
                $choiceKav = "n"
            }
            if ($choiceKav -eq 'y' -or $choiceKav -eq 'Y') {
                Write-Host "-- Downloading the 'KGB-B-Gone' utility..." -ForegroundColor Cyan
                $kavUrl = "https://media.kaspersky.com/utilities/ConsumerUtilities/kavremvr.exe"
                $kavPath = "$env:TEMP\kavremvr.exe"
                Invoke-WebRequest -Uri $kavUrl -OutFile $kavPath
                Write-Host "-- Opening kavremvr Tool... Dasvidaniya!" -ForegroundColor Green
                Start-Process $kavPath
            }
        }

        "3" {
            # --- INTERACTIVE NORTON REMOVAL ---
            Write-Host "`nDestroy Norton? It has more popups than a phishing site. [Y/N] (Auto-Skip in 5s): " -NoNewline -ForegroundColor Yellow
            $counterNorton = 5
            while ($counterNorton -gt 0 -and (-not [console]::KeyAvailable)) {
                Write-Host "..$counterNorton " -NoNewline -ForegroundColor Gray
                Start-Sleep -Seconds 1
                $counterNorton--
            }
            if ([console]::KeyAvailable) {
                $choiceNorton = [console]::ReadKey($true).KeyChar
                Write-Host ""
            } else {
                Write-Host "`nNorton is still leeching your RAM. Skipping." -ForegroundColor DarkGray
                $choiceNorton = "n"
            }
            if ($choiceNorton -eq 'y' -or $choiceNorton -eq 'Y') {
                Write-Host "-- Fetching the Norton Exorcism Tool..." -ForegroundColor Cyan
                $nortonUrl = "https://honzik.avcdn.net/setup/norton-suite/release/norton_360_remover.exe"
                $nortonPath = "$env:TEMP\norton_360_remover.exe"
                Invoke-WebRequest -Uri $nortonUrl -OutFile $nortonPath
                Write-Host "-- Burning Norton to the ground..." -ForegroundColor Green
                Write-Host "The Norton demon has been cast out! ✝️🔥" -ForegroundColor Green
                Write-Host "------------------- YOUR RAM IS FREE AT LAST -------------------" -ForegroundColor Gray
                Start-Process $nortonPath
            }
        }

        "4" {
            # --- INTERACTIVE AVG REMOVAL ---
            Write-Host "`nWipe out AVG? It's just Avast wearing a fake mustache. Eliminate it? [Y/N] (Auto-Skip in 5s): " -NoNewline -ForegroundColor Yellow
            $counterAvg = 5
            while ($counterAvg -gt 0 -and (-not [console]::KeyAvailable)) {
                Write-Host "..$counterAvg " -NoNewline -ForegroundColor Gray
                Start-Sleep -Seconds 1
                $counterAvg--
            }
            if ([console]::KeyAvailable) {
                $choiceAvg = [console]::ReadKey($true).KeyChar
                Write-Host ""
            } else {
                Write-Host "`nAVG remains. Your RAM is crying in the corner." -ForegroundColor DarkGray
                $choiceAvg = "n"
            }
            if ($choiceAvg -eq 'y' -or $choiceAvg -eq 'Y') {
                Write-Host "-- Fetching the AVG 'Clear-Cut' Machete..." -ForegroundColor Cyan
                $avgUrl = "https://honzik.avcdn.net/setup/avg-av/release/avg_av_clear.exe"
                $avgPath = "$env:TEMP\avg_av_clear.exe"
                Invoke-WebRequest -Uri $avgUrl -OutFile $avgPath
                Write-Host "-- Clearing the trash... Goodbye, AVG!" -ForegroundColor Green
                Start-Process $avgPath
            }
        }

        "q" { Write-Host "`nExiting Junkware Menu..." -ForegroundColor Green }
        default { if ($menuChoice) { Write-Host "`nInvalid option, try again." -ForegroundColor Red } }
    }

    # Clear keyboard buffer
    while ([console]::KeyAvailable) { [console]::ReadKey($true) | Out-Null }

} while ($menuChoice -ne "q")

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

# --- Interactive Windows Defender Purge (Hybrid Recovery Edition) ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "Nuke Windows Defender? (WARNING: Flying solo after this) [Y/N] (Auto-Skip in 5s): " -NoNewline -ForegroundColor Red

$counter = 5
while ($counter -gt 0 -and (-not [console]::KeyAvailable)) {
    Write-Host "..$counter " -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
    $counter--
}

if ([console]::KeyAvailable) {
    $choice = [console]::ReadKey($true).KeyChar
    Write-Host ""
} else {
    Write-Host "`nDefender lives to nag another day." -ForegroundColor DarkGray
    $choice = "n"
}

if ($choice -eq 'y' -or $choice -eq 'Y') {
    # Fallback if PSScriptRoot is empty (when running code as a block/selection)
    $rootPath = if ([string]::IsNullOrEmpty($PSScriptRoot)) { Get-Location } else { $PSScriptRoot }
    $minSudoPath = Join-Path $rootPath "MinSudo.exe"

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
            
            # STAGE A: Dynamic Scraping (Always try for the latest bleeding-edge version first)
            Write-Host ">> Attempting to scrape latest release... " -ForegroundColor Yellow -NoNewline
            $gitMeta = & curl -L -s -H "User-Agent: $ua" "https://github.com/M2Team/NanaRun/releases/latest"
            if ($gitMeta -match 'href="([^"]+NanaRun[^"]+\.zip)"') {
                $url = if ($matches[1] -like "http*") { $matches[1] } else { "https://github.com" + $matches[1] }
                & curl -L -H "User-Agent: $ua" -o "$tempZip" "$url" 2>$null
                if ((Test-Path $tempZip) -and (Get-Item $tempZip).Length -gt 10000) { 
                    $downloaded = $true
                    Write-Host "[OK: DYNAMIC]" -ForegroundColor Green
                }
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
            Remove-Item $tempZip, $extractDir -Recurse -Force -ErrorAction SilentlyContinue
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
"TamperProtection"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"RunAsPPL"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]
"LsaConfigFlags"=dword:00000000
"RunAsPPL"=dword:00000000
"RunAsPPLBoot"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Config]
"VulnerableDriverBlocklistEnable"=dword:00000000

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
        Remove-Item $tempReg -Force -ErrorAction SilentlyContinue

        # Self-destruct: Removing the elevation engine to leave the Desktop clean.
        if (Test-Path $minSudoPath) {
            Write-Host ">> Evaporating elevation engine from the workspace... " -ForegroundColor Gray -NoNewline
            Remove-Item $minSudoPath -Force -ErrorAction SilentlyContinue
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
Write-Host "Do you want to verify Valorant requirements? [Y/N] (Default: N in 5s): " -NoNewline

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
    $runCheck = "n"
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
            # --- ENABLE SECTION (User pressed Y or Timeout) ---
            Write-Host "Applying kernel-level security fixes..." -ForegroundColor Green
            & dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
            & bcdedit.exe /set hypervisorlaunchtype auto
            Set-ItemProperty -Path $hvciPath -Name "Enabled" -Value 1
            Write-Host "SUCCESS: Protection Enabled. PLEASE REBOOT." -ForegroundColor Cyan
        } else {
            # --- DISABLE SECTION (User explicitly pressed N) ---
            Write-Host "User opted to disable features. Reverting..." -ForegroundColor Red
            & dism.exe /online /disable-feature /featurename:VirtualMachinePlatform /norestart
            & bcdedit.exe /set hypervisorlaunchtype off
            Set-ItemProperty -Path $hvciPath -Name "Enabled" -Value 0 -ErrorAction SilentlyContinue
            Write-Host "SUCCESS: Protection Disabled. PLEASE REBOOT." -ForegroundColor Cyan
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
    "C:\Program Files\Tools\Config"
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

# 1. Global Language Dictionary (22 Languages)
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

    # Remove DNS policies from HKLM ONLY for Brave to UNLOCK the button in the UI
    if ($basePath -like "*BraveSoftware*") {
        Remove-ItemProperty -Path $basePath -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $basePath -Name "DnsOverHttpsTemplates" -ErrorAction SilentlyContinue
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
    "SyncDisabled"               = 1        # Disable Sync
    "DefaultBrowserSettingEnabled" = 0      # Don't Check Default Browser
    "DeveloperToolsAvailability" = 1        # Enable Developer Mode
    "ChromeCleanupEnabled"       = 0        # Disable Chrome Cleanup Tool
    "ChromeCleanupReportingEnabled" = 0     # Disable Cleanup reporting
}

foreach ($name in $chromeTweaks.Keys) {
    Set-ItemProperty -Path $chromeOnlyPath -Name $name -Value $chromeTweaks[$name] -Type DWord -ErrorAction SilentlyContinue
}

# --- BRAVE SPECIFIC DEBLOAT ---
# Policies for Brave-specific features (Web3, Rewards, and AI)
$braveOnlyPath = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
$braveTweaks = @{
    "BraveVPNDisabled"           = 1        # Remove Brave VPN button and service
    "BraveWalletDisabled"        = 1        # Disable the built-in Crypto Wallet
    "BraveAIChatEnabled"         = 0        # Disable "Leo" AI Chat
    "BraveRewardsDisabled"       = 1        # Disable Brave Rewards/Ads
    "BraveTalkDisabled"          = 1        # Disable the "Brave Talk" video call feature
    "BraveNewsDisabled"          = 1        # Disable the Brave News feed on new tabs
    "SyncDisabled"               = 1        # Disable Sync
    "DefaultBrowserSettingEnabled" = 0      # Don't Check Default Browser
    "DeveloperToolsAvailability" = 1        # Enable Developer Mode
    "BuiltInDnsClientEnabled"    = 1        # Unlocks the internal DNS client (Button)
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

# --- AUTOMATIC APP INSTALLATION (UNATTENDED) ---
Write-Host "`n[MODULE] Deploying Essential Applications..." -ForegroundColor Cyan

$appsToInstall = @(
    @{ Name = "UpNote"; ID = "9mv7690m8f5n" },
    @{ Name = "LibreWolf"; ID = "9nvn9sz8kfd7" },
    @{ Name = "ShareX"; ID = "ShareX.ShareX" },
    @{ Name = "CrystalDiskInfo"; ID = "CrystalDewWorld.CrystalDiskInfo" },
    @{ Name = "SSD Booster"; ID = "9nvmxq4ps0lb" },
    @{ Name = "PDFgear"; ID = "PDFgear.PDFgear" },
    @{ Name = "Calibre"; ID = "Calibre.calibre" },
    @{ Name = "Simple Radio Online"; ID = "9n4hx2x3f88h" }
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

# ==============================================================================
# DISK INTELLIGENCE & SMART ANALYSIS MODULE
# ==============================================================================

Write-Host " ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host " ║        DISK INTELLIGENCE & SMART ANALYSIS MODULE         ║" -ForegroundColor Cyan
Write-Host " ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# --- LOCALIZATION ENGINE ---
$currentLang = [System.Globalization.CultureInfo]::CurrentUICulture.Name

$langMap = @{
    "pt*"    = @{ Update = "Atualizando dados SMART..."; LogGen = "Log SMART gerado na pasta Temp."; Analyzing = "Analisando Armazenamento..."; NoDrives = "Nenhum disco detectado."; Name = "NOME"; Letter = "LETRA"; Serial = "SERIAL"; FW = "FIRMWARE"; Health = "SAÚDE"; Temp = "TEMPERATURA"; Power = "LIGADO POR"; Cycles = "Ciclos"; Interface = "INTERFACE"; Standard = "PADRÃO"; Features = "RECURSOS"; Type = "TIPO"; Clean = "Arquivo temporário removido."; HostRW = "L/G HOSPED."; Read = "L"; Write = "G" }
    "en*"    = @{ Update = "Updating SMART data..."; LogGen = "SMART log generated in Temp folder."; Analyzing = "Analyzing Storage..."; NoDrives = "No drives detected."; Name = "NAME"; Letter = "LETTER"; Serial = "SERIAL"; FW = "FIRMWARE"; Health = "HEALTH"; Temp = "TEMPERATURE"; Power = "POWER ON"; Cycles = "Cycles"; Interface = "INTERFACE"; Standard = "STANDARD"; Features = "FEATURES"; Type = "TYPE"; Clean = "Temporary log file removed."; HostRW = "HOST R/W"; Read = "R"; Write = "W" }
    "es*"    = @{ Update = "Actualizando datos SMART..."; LogGen = "Log SMART generado en Temp."; Analyzing = "Analizando almacenamiento..."; NoDrives = "No se detectaron discos."; Name = "NOMBRE"; Letter = "LETRA"; Serial = "SERIAL"; FW = "FIRMWARE"; Health = "ESTADO"; Temp = "TEMPERATURA"; Power = "ENCENDIDO"; Cycles = "Ciclos"; Interface = "INTERFAZ"; Standard = "ESTÁNDAR"; Features = "FUNCIONES"; Type = "TIPO"; Clean = "Archivo temporal eliminado."; HostRW = "E/L HOST"; Read = "L"; Write = "E" }
    "fr*"    = @{ Update = "Mise à jour SMART..."; LogGen = "Log SMART généré dans Temp."; Analyzing = "Analyse du stockage..."; NoDrives = "Aucun disque détecté."; Name = "NOM"; Letter = "LETTRE"; Serial = "SÉRIE"; FW = "FIRMWARE"; Health = "SANTÉ"; Temp = "TEMPÉRATURE"; Power = "HEURES"; Cycles = "Cycles"; Interface = "INTERFACE"; Standard = "NORME"; Features = "CARACTÉRIST."; Type = "TYPE"; Clean = "Fichier temporaire supprimé."; HostRW = "E/L HÔTE"; Read = "L"; Write = "E" }
    "de*"    = @{ Update = "SMART-Daten werden aktualisiert..."; LogGen = "SMART-Log in Temp erstellt."; Analyzing = "Speicheranalyse..."; NoDrives = "Keine Laufwerke gefunden."; Name = "NAME"; Letter = "PFAD"; Serial = "SERIE"; FW = "FIRMWARE"; Health = "ZUSTAND"; Temp = "TEMPERATUR"; Power = "BETRIEBSZEIT"; Cycles = "Zyklen"; Interface = "SCHNITTSTELLE"; Standard = "STANDARD"; Features = "FUNKTIONEN"; Type = "TYP"; Clean = "Temporäre Datei gelöscht."; HostRW = "HOST L/S"; Read = "L"; Write = "S" }
    "it*"    = @{ Update = "Aggiornamento dati SMART..."; LogGen = "Log SMART generato in Temp."; Analyzing = "Analisi archiviazione..."; NoDrives = "Nessun disco rilevato."; Name = "NOME"; Letter = "LETTERA"; Serial = "SERIALE"; FW = "FIRMWARE"; Health = "STATO"; Temp = "TEMPERATURA"; Power = "ACCESO DA"; Cycles = "Cicli"; Interface = "INTERFACCIA"; Standard = "STANDARD"; Features = "FUNZIONI"; Type = "TIPO"; Clean = "File temporaneo rimosso."; HostRW = "R/S HOST"; Read = "R"; Write = "S" }
    "ru*"    = @{ Update = "Обновление SMART..."; LogGen = "Лог SMART создан в Temp."; Analyzing = "Анализ хранилища..."; NoDrives = "Диски не обнаружены."; Name = "ИМЯ"; Letter = "БУКВА"; Serial = "СЕРИЙНЫЙ"; FW = "ПРОШИВКА"; Health = "СТАТУС"; Temp = "ТЕМПЕРАТУРА"; Power = "ВРЕМЯ РАБОТЫ"; Cycles = "Циклы"; Interface = "ИНТЕРФЕЙС"; Standard = "СТАНДАРТ"; Features = "ФУНКЦИИ"; Type = "ТИП"; Clean = "Временный файл удален."; HostRW = "ЧТ/ЗП ХОСТ"; Read = "Ч"; Write = "З" }
    "zh-TW*" = @{ Update = "更新 SMART 數據..."; LogGen = "SMART 日誌已生成。"; Analyzing = "正在分析存儲..."; NoDrives = "未檢測到磁碟。"; Name = "名稱"; Letter = "磁碟代號"; Serial = "序號"; FW = "固件"; Health = "健康狀態"; Temp = "溫度"; Power = "通電時間"; Cycles = "次數"; Interface = "介面"; Standard = "標準"; Features = "特徵"; Type = "類型"; Clean = "臨時文件已刪除。"; HostRW = "主機讀寫"; Read = "讀"; Write = "寫" }
    "zh-CN*" = @{ Update = "更新 SMART 数据..."; LogGen = "SMART 日志已生成。"; Analyzing = "正在分析存储..."; NoDrives = "未检测到磁盘。"; Name = "名称"; Letter = "驱动器号"; Serial = "序列号"; FW = "固件"; Health = "健康状态"; Temp = "温度"; Power = "通电时间"; Cycles = "次数"; Interface = "接口"; Standard = "标准"; Features = "特征"; Type = "类型"; Clean = "临时文件已删除。"; HostRW = "主机读写"; Read = "读"; Write = "写" }
    "ar*"    = @{ Update = "تحديث بيانات SMART..."; LogGen = "تم إنشاء سجل SMART."; Analyzing = "تحليل التخزين..."; NoDrives = "لم يتم اكتشاف أقراص."; Name = "الاسم"; Letter = "الحرف"; Serial = "الرقم"; FW = "البرنامج"; Health = "الحالة"; Temp = "الحرارة"; Power = "وقت التشغيل"; Cycles = "دورات"; Interface = "الواجهة"; Standard = "المعيار"; Features = "الميزات"; Type = "النوع"; Clean = "تم حذف الملف المؤقت."; HostRW = "ق/ك المضيف"; Read = "ق"; Write = "ك" }
    "cs*"    = @{ Update = "Aktualizace SMART..."; LogGen = "SMART log vytvořen."; Analyzing = "Analýza úložiště..."; NoDrives = "Nebyl nalezen disk."; Name = "NÁZEV"; Letter = "PÍSMENO"; Serial = "SÉRIOVÉ"; FW = "FIRMWARE"; Health = "STAV"; Temp = "TEPLOTA"; Power = "ZAPNUTO"; Cycles = "Cykly"; Interface = "ROZHRANÍ"; Standard = "STANDARD"; Features = "FUNKCE"; Type = "TYP"; Clean = "Dočasný soubor smazán."; HostRW = "HOST Č/Z"; Read = "Č"; Write = "Z" }
    "da*"    = @{ Update = "Opdaterer SMART..."; LogGen = "SMART-log oprettet."; Analyzing = "Analyserer lager..."; NoDrives = "Ingen diske fundet."; Name = "NAVN"; Letter = "BOGSTAV"; Serial = "SERIENUMMER"; FW = "FIRMWARE"; Health = "HELBREDE"; Temp = "TEMPERATUR"; Power = "TÆNDT I"; Cycles = "Cykler"; Interface = "GRÆNSEFLADE"; Standard = "STANDARD"; Features = "FUNKTIONER"; Type = "TYPE"; Clean = "Midlertidig fil slettet."; HostRW = "VÆRT L/S"; Read = "L"; Write = "S" }
    "nl*"    = @{ Update = "SMART-gegevens bijwerken..."; LogGen = "SMART-log gegenereerd."; Analyzing = "Opslag analyseren..."; NoDrives = "Geen schijven gedetecteerd."; Name = "NAAM"; Letter = "LETTER"; Serial = "SERIENUMMER"; FW = "FIRMWARE"; Health = "GEZONDHEID"; Temp = "TEMPERATUUR"; Power = "AAN-TIJD"; Cycles = "Cycli"; Interface = "INTERFACE"; Standard = "STANDAARD"; Features = "FUNCTIES"; Type = "TYPE"; Clean = "Tijdelijk bestand verwijderd."; HostRW = "HOST L/S"; Read = "L"; Write = "S" }
    "fi*"    = @{ Update = "Päivitetään SMART..."; LogGen = "SMART-loki luotu."; Analyzing = "Analysoidaan tallennustilaa..."; NoDrives = "Levyjä ei löytynyt."; Name = "NIMI"; Letter = "KIRJAIN"; Serial = "SARJANRO"; FW = "LAITE-OHJ"; Health = "KUNTO"; Temp = "LÄMPÖTILA"; Power = "KÄYTTÖAIKA"; Cycles = "Syklit"; Interface = "LIITÄNTÄ"; Standard = "STANDARDI"; Features = "OMINAIS."; Type = "TYYPPI"; Clean = "Väliaikaistiedosto poistettu."; HostRW = "HOST L/K"; Read = "L"; Write = "K" }
    "el*"    = @{ Update = "Ενημέρωση SMART..."; LogGen = "Το SMART log δημιουργήθηκε."; Analyzing = "Ανάλυση αποθήκευσης..."; NoDrives = "Δεν βρέθηκαν δίσκοι."; Name = "ΟΝΟΜΑ"; Letter = "ΓΡΑΜΜΑ"; Serial = "ΣΕΙΡΙΑΚΟΣ"; FW = "FIRMWARE"; Health = "ΥΓΕΙΑ"; Temp = "ΘΕΡΜΟΚΡΑΣΙΑ"; Power = "ΩΡΕΣ"; Cycles = "Κύκλοι"; Interface = "ΔΙΑΣΥΝΔΕΣΗ"; Standard = "ΠΡΟΤΥΠΟ"; Features = "ΧΑΡΑΚΤΗΡ."; Type = "ΤΥΠΟΣ"; Clean = "Το προσωρινό αρχείο διαγράφηκε."; HostRW = "HOST A/E"; Read = "A"; Write = "E" }
    "he*"    = @{ Update = "מעדכן נתוני SMART..."; LogGen = "יומן SMART נוצר."; Analyzing = "מנתח אחסון..."; NoDrives = "לא נמצאו כוננים."; Name = "שם"; Letter = "אות"; Serial = "מספר סידורי"; FW = "קושחה"; Health = "מצב"; Temp = "טמפרטורה"; Power = "זמן פעולה"; Cycles = "מחזורים"; Interface = "ממשק"; Standard = "תקן"; Features = "תכונות"; Type = "סוג"; Clean = "קובץ זמני הוסר."; HostRW = "ק/כ מארח"; Read = "ק"; Write = "כ" }
    "hu*"    = @{ Update = "SMART adatok frissítése..."; LogGen = "SMART napló létrehozva."; Analyzing = "Tárhely elemzése..."; NoDrives = "Nem található lemez."; Name = "NÉV"; Letter = "BETŰ"; Serial = "SOROZATSZÁM"; FW = "FIRMWARE"; Health = "ÁLLAPOT"; Temp = "HŐMÉRSÉKLET"; Power = "ÜZEMIDŐ"; Cycles = "Ciklusok"; Interface = "INTERFÉSZ"; Standard = "SZABVÁNY"; Features = "FUNKCIÓK"; Type = "TÍPUS"; Clean = "Ideiglenes fájl törölve."; HostRW = "HOST O/Í"; Read = "O"; Write = "Í" }
    "ja*"    = @{ Update = "SMART情報を更新中..."; LogGen = "ログを生成しました。"; Analyzing = "ストレージを分析中..."; NoDrives = "ディスクが見つかりません。"; Name = "名前"; Letter = "ドライブ"; Serial = "シリアル"; FW = "ファームウェア"; Health = "健康状態"; Temp = "温度"; Power = "使用時間"; Cycles = "回数"; Interface = "インターフェース"; Standard = "規格"; Features = "機能"; Type = "タイプ"; Clean = "一時ファイルを削除しました。"; HostRW = "ホスト読書"; Read = "読"; Write = "書" }
    "ko*"    = @{ Update = "SMART 데이터 업데이트 중..."; LogGen = "로그가 생성되었습니다."; Analyzing = "저장 장치 분석 중..."; NoDrives = "디스크를 찾을 수 없습니다."; Name = "이름"; Letter = "드라이브"; Serial = "시리얼"; FW = "펌웨어"; Health = "상태"; Temp = "온도"; Power = "사용 시간"; Cycles = "횟수"; Interface = "인터페이스"; Standard = "표준"; Features = "기능"; Type = "유형"; Clean = "임시 파일이 삭제되었습니다."; HostRW = "호스트 읽기/쓰기"; Read = "읽"; Write = "쓰" }
    "no*"    = @{ Update = "Oppdaterer SMART..."; LogGen = "SMART-logg generert."; Analyzing = "Analyserer lagring..."; NoDrives = "Ingen disker funnet."; Name = "NAVN"; Letter = "BOKSTAV"; Serial = "SERIENUMMER"; FW = "FIRMWARE"; Health = "HELSE"; Temp = "TEMPERATUR"; Power = "DRIFTSTID"; Cycles = "Sykluser"; Interface = "GRENSESNITT"; Standard = "STANDARD"; Features = "FUNKSJONER"; Type = "TYPE"; Clean = "Midlertidig fil slettet."; HostRW = "HOST L/S"; Read = "L"; Write = "S" }
    "pl*"    = @{ Update = "Aktualizacja SMART..."; LogGen = "Log SMART wygenerowany."; Analyzing = "Analiza pamięci..."; NoDrives = "Nie wykryto dysków."; Name = "NAZWA"; Letter = "LITERA"; Serial = "SÉRYJNY"; FW = "FIRMWARE"; Health = "STAN"; Temp = "TEMPERATURA"; Power = "CZAS PRACY"; Cycles = "Cykle"; Interface = "INTERFEJS"; Standard = "STANDARD"; Features = "FUNKCJE"; Type = "TYP"; Clean = "Plik tymczasowy usunięty."; HostRW = "HOST O/Z"; Read = "O"; Write = "Z" }
    "sv*"    = @{ Update = "Uppdaterar SMART..."; LogGen = "SMART-logg skapad."; Analyzing = "Analyserar lagring..."; NoDrives = "Inga diskar hittades."; Name = "NAMN"; Letter = "BOKSTAV"; Serial = "SERIENUMMER"; FW = "FIRMWARE"; Health = "HÄLSA"; Temp = "TEMPERATUR"; Power = "DRIFTTID"; Cycles = "Cykler"; Interface = "GRÄNSSNITT"; Standard = "STANDARD"; Features = "FUNKTIONER"; Type = "TYP"; Clean = "Temporär fil borttagen."; HostRW = "VÄRT L/S"; Read = "L"; Write = "S" }
    "tr*"    = @{ Update = "SMART verileri güncelleniyor..."; LogGen = "SMART günlüğü oluşturuldu."; Analyzing = "Depolama analiz ediliyor..."; NoDrives = "Disk bulunamadı."; Name = "AD"; Letter = "HARF"; Serial = "SERİ NO"; FW = "YAZILIM"; Health = "SAĞLIK"; Temp = "SICAKLIK"; Power = "ÇALIŞMA"; Cycles = "Döngü"; Interface = "ARAYÜZ"; Standard = "STANDART"; Features = "ÖZELLİKLER"; Type = "TÜR"; Clean = "Geçici dosya silindi."; HostRW = "ANA OKU/YAZ"; Read = "O"; Write = "Y" }
}

$UI = $langMap["en*"] # Default
foreach ($pattern in $langMap.Keys) { if ($currentLang -like $pattern) { $UI = $langMap[$pattern]; break } }

# --- CONFIGURATION ---
$cdiExecutable = "C:\Program Files\CrystalDiskInfo\DiskInfo64.exe" 
$workPath      = Join-Path $env:TEMP "DEBUG_DISK.txt"
$cdiDir        = [System.IO.Path]::GetDirectoryName($cdiExecutable)
$sourceLog     = Join-Path $cdiDir "DiskInfo.txt"

try {
    Write-Host "`n [🔄] $($UI.Update)" -ForegroundColor Yellow

    if (Test-Path $cdiExecutable) {
        Start-Process -FilePath $cdiExecutable -ArgumentList "/CopyExit" -Wait
        if (Test-Path $sourceLog) {
            Move-Item -Path $sourceLog -Destination $workPath -Force
            Write-Host " [✅] $($UI.LogGen)" -ForegroundColor Green
        }
    } else {
        Write-Host " [!] CrystalDiskInfo not found." -ForegroundColor Red
        if (-not (Test-Path $workPath)) { return }
    }

    Write-Host " [🔍] $($UI.Analyzing) ($currentLang)" -ForegroundColor Cyan
    if (-not (Test-Path $workPath)) { return }

    try { $rawContent = Get-Content $workPath -Raw -Encoding UTF8 }
    catch { $rawContent = Get-Content $workPath -Raw }

    $rawContent = $rawContent -replace "`0","" -replace "`r",""
    $pattern = '(?ms)^-+\s*\n\s*\(\d+\).*?\n-+\s*\n(.*?)(?=^-+\s*\n\s*\(\d+\)|\z)'
    $diskBlocks = [regex]::Matches($rawContent, $pattern)

    if ($diskBlocks.Count -eq 0) { Write-Host " [!] $($UI.NoDrives)" -ForegroundColor Red; return }

    foreach ($item in $diskBlocks) {
        $block = $item.Groups[1].Value
        function Get-Val($regex) { if ($block -match $regex) { return $matches[1].Trim() }; return "" }

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

        # Handle Standard fallback
        if (-not $props.Standard) {
            $major = Get-Val '(?m)^\s*Major Version\s*:\s*(.+)$'
            $minor = Get-Val '(?m)^\s*Minor Version\s*:\s*(.+)$'
            $props.Standard = "$major | $minor".Trim(" |")
        }

        # Health Formatting
        $HealthPct = ""; if ($props.Health -match '\((.*?)\)') { $HealthPct = $matches[1]; $props.Health = ($props.Health -replace '\(.*?\)', '').Trim() }
        if (-not $HealthPct -and $props.Health -match 'Healthy|Good|Saudável') { $HealthPct = "100 %" }
        if ($props.Temp -match '^(.+?)\s*\(') { $props.Temp = $matches[1].Trim() }

        $hColor = "White"
        if ($props.Health -match 'Healthy|Good|Saudável') { $hColor = "Green" }
        elseif ($props.Health -match 'Caution|Warning|Alerta') { $hColor = "Yellow" }
        elseif ($props.Health -match 'Bad|Fail|Ruim') { $hColor = "Red" }

        # Output UI
        Write-Host "`n----------------------------------------------------" -ForegroundColor DarkGray
        Write-Host " $($UI.Name):".PadRight(15) -NoNewline; Write-Host $props.Model -ForegroundColor White
        Write-Host " $($UI.Letter):".PadRight(15) -NoNewline; Write-Host $props.Letter -ForegroundColor Cyan
        Write-Host " $($UI.Serial):".PadRight(15) -NoNewline; Write-Host $props.Serial -ForegroundColor White
        Write-Host " $($UI.FW):".PadRight(15) -NoNewline; Write-Host $props.FW -ForegroundColor White
        Write-Host " $($UI.Health):".PadRight(15) -NoNewline; Write-Host "$($props.Health) $HealthPct" -ForegroundColor $hColor
        Write-Host " $($UI.Temp):".PadRight(15) -NoNewline; Write-Host $props.Temp -ForegroundColor Cyan
        Write-Host " $($UI.Power):".PadRight(15) -NoNewline; Write-Host "$($props.Hours) | $($UI.Cycles): $($props.Count)" -ForegroundColor White
        Write-Host " $($UI.Interface):".PadRight(15) -NoNewline; Write-Host $props.Interface -ForegroundColor Magenta
        Write-Host " $($UI.Standard):".PadRight(15) -NoNewline; Write-Host $props.Standard -ForegroundColor White
        Write-Host " $($UI.Features):".PadRight(15) -NoNewline; Write-Host $props.Features -ForegroundColor White
        
        if ($props.Rotation) {
            Write-Host " $($UI.Type):".PadRight(15) -NoNewline; Write-Host "HDD ($($props.Rotation))" -ForegroundColor Magenta
        } else {
            Write-Host " $($UI.Type):".PadRight(15) -NoNewline; Write-Host "SSD / NVMe" -ForegroundColor Green
            Write-Host " $($UI.HostRW):".PadRight(15) -NoNewline; Write-Host "$($UI.Read): $($props.Reads) | $($UI.Write): $($props.Writes)" -ForegroundColor Cyan
        }
        Write-Host "----------------------------------------------------" -ForegroundColor DarkGray
    }
} finally {
    if (Test-Path $workPath) { 
        Remove-Item $workPath -Force
        Write-Host "`n [🗑️] $($UI.Clean)" -ForegroundColor Gray 
    }
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
    return
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
    return
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

# --- INSTALL APPS VIA WINGET (WITH POPUP TIMEOUT) ---
Write-Host "`n[MODULE] Starting Interactive App Installation..." -ForegroundColor Cyan
$appsToInstall = @(
    @{ Name = "FluentFlyout"; ID = "9n45nsm4tnbp" },
    @{ Name = "TubeDigger"; ID = "TubeDigger.TubeDigger" },
    @{ Name = "SignalRgb"; ID = "WhirlwindFX.SignalRgb" },
    @{ Name = "Hydra"; ID = "HydraLauncher.Hydra" },
    @{ Name = "Signal"; ID = "xp89119p9f2pcq" },
    @{ Name = "Sticky Password"; ID = "xp8lt301zl525k" },
    @{ Name = "Antigravity"; ID = "Google.Antigravity" },
    @{ Name = "WhatsApp"; ID = "9nksqgp7f2nh" },
    @{ Name = "Outlook"; ID = "9nrx63209r7b" },
    @{ Name = "OneDrive"; ID = "Microsoft.OneDrive" },
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

$packagesToInstall = @(
    "7zip"
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

# --- 9. GIT CONTEXT MENU OPTIMIZATION (FORCE SHIFT-ONLY) ---
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
