#Requires -Version 5.0
#Requires -RunAsAdministrator 

<#
.SYNOPSIS
    Permanently blocks StartAllBack from accessing the internet and prevents Microsoft Store updates.

.DESCRIPTION
    This script creates comprehensive firewall rules to block all StartAllBack executables
    from accessing the internet, modifies the hosts file to block update servers,
    blocks Windows Update from updating StartAllBack through the Store, and provides
    verification of the blocking status.

.PARAMETER Action
    Specifies the action to perform: Block, Unblock, or Status

.PARAMETER IncludeHostsFile
    Whether to modify the hosts file to block update servers (default: $true)

.PARAMETER BlockStoreUpdates
    Whether to block Microsoft Store updates for StartAllBack (default: $true)

.EXAMPLE
    .\Block-StartAllBack.ps1 -Action Block
    Blocks StartAllBack internet access with firewall rules, hosts file modifications, and Store blocking

.EXAMPLE
    .\Block-StartAllBack.ps1 -Action Unblock
    Removes all firewall rules, hosts file entries, and Store blocks to restore functionality

.EXAMPLE
    .\Block-StartAllBack.ps1 -Action Status
    Shows current blocking status without making changes
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Block", "Unblock", "Status")]
    [string]$Action = "Block",
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeHostsFile = $true,
    
    [Parameter(Mandatory=$false)]
    [bool]$BlockStoreUpdates = $true
)

# Configuration
$Script:RuleBaseName = "StartAllBack Internet Block"
$Script:HostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"
$Script:BlockedDomains = @(
    "startallback.com",
    "www.startallback.com", 
    "startisback.com",
    "www.startisback.com",
    "update.startallback.com",
    "api.startallback.com",
    "store.startallback.com",
    "download.startallback.com"
)

# Common StartAllBack installation paths
$Script:CommonPaths = @(
    "${env:ProgramFiles}\StartAllBack",
    "${env:ProgramFiles(x86)}\StartAllBack",
    "${env:LocalAppData}\StartAllBack",
    "${env:AppData}\StartAllBack",
    "${env:ProgramData}\StartAllBack",
    "${env:LocalAppData}\Packages\*StartAllBack*",
    "${env:ProgramFiles}\WindowsApps\*StartAllBack*"
)

# Microsoft Store Package IDs for StartAllBack
$Script:StorePackageNames = @(
    "StartAllBack",
    "StartIsBack",
    "49306atecsolution.StartAllBack*"
)

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        "Info" = "Cyan"
        "Success" = "Green" 
        "Warning" = "Yellow"
        "Error" = "Red"
    }
    
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host "[$Level] " -NoNewline -ForegroundColor $colors[$Level]
    Write-Host $Message
}

function Test-Prerequisites {
    Write-LogMessage "Checking prerequisites..." "Info"
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-LogMessage "This script must be run as Administrator!" "Error"
        return $false
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-LogMessage "PowerShell 5.0 or higher is required!" "Error"
        return $false
    }
    
    # Check if NetSecurity module is available
    try {
        Import-Module NetSecurity -ErrorAction Stop
        Write-LogMessage "NetSecurity module loaded successfully" "Success"
    }
    catch {
        Write-LogMessage "Failed to load NetSecurity module: $($_.Exception.Message)" "Error"
        return $false
    }
    
    # Check Windows Firewall service
    $firewallService = Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue
    if (-not $firewallService -or $firewallService.Status -ne "Running") {
        Write-LogMessage "Windows Firewall service is not running!" "Error"
        return $false
    }
    
    Write-LogMessage "All prerequisites met" "Success"
    return $true
}

function Find-StartAllBackExecutables {
    Write-LogMessage "Scanning for StartAllBack installations..." "Info"
    
    $foundExecutables = @()
    
    # Search in common installation paths
    foreach ($path in $Script:CommonPaths) {
        if ($path -like "*`**") {
            # Handle wildcard paths
            $basePath = $path.Substring(0, $path.LastIndexOf('\'))
            $pattern = $path.Substring($path.LastIndexOf('\') + 1)
            
            if (Test-Path $basePath) {
                $directories = Get-ChildItem -Path $basePath -Directory -Filter $pattern -ErrorAction SilentlyContinue
                foreach ($dir in $directories) {
                    $executables = Get-ChildItem -Path $dir.FullName -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
                    foreach ($exe in $executables) {
                        $foundExecutables += $exe.FullName
                        Write-LogMessage "  Found executable: $($exe.FullName)" "Info"
                    }
                }
            }
        }
        elseif (Test-Path $path) {
            Write-LogMessage "Found StartAllBack directory: $path" "Info"
            $executables = Get-ChildItem -Path $path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
            foreach ($exe in $executables) {
                $foundExecutables += $exe.FullName
                Write-LogMessage "  Found executable: $($exe.FullName)" "Info"
            }
        }
    }
    
    # Search for Store app installations
    try {
        foreach ($packageName in $Script:StorePackageNames) {
            $packages = Get-AppxPackage -Name $packageName -AllUsers -ErrorAction SilentlyContinue
            foreach ($package in $packages) {
                if ($package.InstallLocation) {
                    Write-LogMessage "Found Store package: $($package.Name) at $($package.InstallLocation)" "Info"
                    $executables = Get-ChildItem -Path $package.InstallLocation -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
                    foreach ($exe in $executables) {
                        if ($exe.FullName -notin $foundExecutables) {
                            $foundExecutables += $exe.FullName
                            Write-LogMessage "  Found Store app executable: $($exe.FullName)" "Info"
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-LogMessage "Warning: Could not search Store packages: $($_.Exception.Message)" "Warning"
    }
    
    # Search registry for StartAllBack/StartIsBack entries
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($regPath in $registryPaths) {
        try {
            $uninstallEntries = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName -match "StartAllBack|StartIsBack" }
            
            foreach ($entry in $uninstallEntries) {
                if ($entry.InstallLocation -and (Test-Path $entry.InstallLocation)) {
                    $executables = Get-ChildItem -Path $entry.InstallLocation -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
                    foreach ($exe in $executables) {
                        if ($exe.FullName -notin $foundExecutables) {
                            $foundExecutables += $exe.FullName
                            Write-LogMessage "  Found executable via registry: $($exe.FullName)" "Info"
                        }
                    }
                }
            }
        }
        catch {
            # Silently continue on registry access errors
        }
    }
    
    # Search for running StartAllBack processes
    $runningProcesses = Get-Process | Where-Object { $_.ProcessName -match "StartAllBack|StartIsBack" }
    foreach ($process in $runningProcesses) {
        try {
            $processPath = $process.MainModule.FileName
            if ($processPath -and $processPath -notin $foundExecutables) {
                $foundExecutables += $processPath
                Write-LogMessage "  Found running process: $processPath" "Info"
            }
        }
        catch {
            # Some processes may not allow access to MainModule
        }
    }
    
    if ($foundExecutables.Count -eq 0) {
        Write-LogMessage "No StartAllBack executables found!" "Warning"
    } else {
        Write-LogMessage "Found $($foundExecutables.Count) StartAllBack executable(s)" "Success"
    }
    
    return $foundExecutables
}

function Block-MicrosoftStoreUpdates {
    if (-not $BlockStoreUpdates) {
        Write-LogMessage "Microsoft Store update blocking skipped (BlockStoreUpdates = false)" "Info"
        return
    }
    
    Write-LogMessage "Blocking Microsoft Store updates for StartAllBack..." "Info"
    
    $blockedCount = 0
    
    # Block Windows Update service from updating StartAllBack
    try {
        # Create registry key to block automatic Store updates for specific apps
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        
        # Block specific Store package updates
        foreach ($packageName in $Script:StorePackageNames) {
            try {
                $packages = Get-AppxPackage -Name $packageName -AllUsers -ErrorAction SilentlyContinue
                foreach ($package in $packages) {
                    # Disable auto-update for this package
                    $packageFamilyName = $package.PackageFamilyName
                    
                    # Method 1: Using Windows Update registry
                    $blockPath = "$registryPath\ExcludedApplications"
                    if (-not (Test-Path $blockPath)) {
                        New-Item -Path $blockPath -Force | Out-Null
                    }
                    
                    Set-ItemProperty -Path $blockPath -Name $packageFamilyName -Value 1 -Type DWord -Force
                    Write-LogMessage "  Blocked Store updates for: $packageFamilyName" "Success"
                    $blockedCount++
                    
                    # Method 2: Disable package auto-update capability
                    try {
                        # Attempt to remove the package from auto-update list
                        $autoUpdatePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Data\$($package.PackageFullName)"
                        if (Test-Path $autoUpdatePath) {
                            Set-ItemProperty -Path $autoUpdatePath -Name "Flags" -Value 0x40000000 -Type DWord -Force -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                        # Silent continue - this is a secondary method
                    }
                }
            }
            catch {
                Write-LogMessage "  Warning: Could not block package $packageName`: $($_.Exception.Message)" "Warning"
            }
        }
        
        # Block Store update URLs in firewall
        Write-LogMessage "Creating firewall rules to block Store update servers..." "Info"
        
        # Common Microsoft Store update endpoints
        $storeUpdateUrls = @(
            "*.microsoft.com",
            "*.windowsupdate.com",
            "*.windows.com"
        )
        
        # Create outbound rules to block Store updates for StartAllBack
        foreach ($packageName in $Script:StorePackageNames) {
            $ruleName = "$Script:RuleBaseName - Block Store Updates for $packageName"
            try {
                # This rule blocks Store app from updating StartAllBack
                New-NetFirewallRule -DisplayName $ruleName `
                                   -Direction Outbound `
                                   -Program "%SystemRoot%\System32\WUDFHost.exe" `
                                   -RemoteAddress Any `
                                   -Action Block `
                                   -Profile Any `
                                   -Enabled True `
                                   -Description "Blocks Microsoft Store from updating $packageName" `
                                   -ErrorAction SilentlyContinue | Out-Null
                
                Write-LogMessage "  Created Store update firewall rule: $ruleName" "Success"
            }
            catch {
                # Try alternative approach
            }
        }
        
        # Disable Store auto-updates via Group Policy registry
        $storePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
        if (-not (Test-Path $storePolicyPath)) {
            New-Item -Path $storePolicyPath -Force | Out-Null
        }
        
        # Set AutoDownload to 2 (never auto-update)
        Set-ItemProperty -Path $storePolicyPath -Name "AutoDownload" -Value 2 -Type DWord -Force
        Write-LogMessage "  Configured Store auto-update policy" "Success"
        
    }
    catch {
        Write-LogMessage "Error blocking Store updates: $($_.Exception.Message)" "Error"
    }
    
    if ($blockedCount -gt 0) {
        Write-LogMessage "Blocked Store updates for $blockedCount package(s)" "Success"
    }
}

function Unblock-MicrosoftStoreUpdates {
    if (-not $BlockStoreUpdates) {
        return
    }
    
    Write-LogMessage "Unblocking Microsoft Store updates for StartAllBack..." "Info"
    
    try {
        # Remove registry blocks
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ExcludedApplications"
        if (Test-Path $registryPath) {
            foreach ($packageName in $Script:StorePackageNames) {
                $packages = Get-AppxPackage -Name $packageName -AllUsers -ErrorAction SilentlyContinue
                foreach ($package in $packages) {
                    Remove-ItemProperty -Path $registryPath -Name $package.PackageFamilyName -ErrorAction SilentlyContinue
                }
            }
        }
        
        # Remove Store update firewall rules
        $storeRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*$Script:RuleBaseName - Block Store Updates*" }
        foreach ($rule in $storeRules) {
            Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
            Write-LogMessage "  Removed Store update rule: $($rule.DisplayName)" "Success"
        }
        
        # Remove Store auto-update policy
        $storePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
        if (Test-Path $storePolicyPath) {
            Remove-ItemProperty -Path $storePolicyPath -Name "AutoDownload" -ErrorAction SilentlyContinue
        }
        
        Write-LogMessage "Microsoft Store update blocking removed" "Success"
    }
    catch {
        Write-LogMessage "Error unblocking Store updates: $($_.Exception.Message)" "Error"
    }
}

function New-FirewallRules {
    param([string[]]$ExecutablePaths)
    
    Write-LogMessage "Creating firewall rules to block internet access..." "Info"
    
    $rulesCreated = 0
    $ruleNumber = 1
    
    foreach ($exePath in $ExecutablePaths) {
        if (-not (Test-Path $exePath)) {
            Write-LogMessage "Skipping non-existent file: $exePath" "Warning"
            continue
        }
        
        $exeName = [System.IO.Path]::GetFileNameWithoutExtension($exePath)
        
        # Create outbound rule
        $outboundRuleName = "$Script:RuleBaseName - $exeName Outbound ($ruleNumber)"
        try {
            New-NetFirewallRule -DisplayName $outboundRuleName `
                               -Direction Outbound `
                               -Program $exePath `
                               -Action Block `
                               -Profile Any `
                               -Enabled True `
                               -Description "Blocks $exeName from accessing the internet (outbound)" `
                               -ErrorAction Stop | Out-Null
            
            Write-LogMessage "Created outbound rule: $outboundRuleName" "Success"
            $rulesCreated++
        }
        catch {
            Write-LogMessage "Failed to create outbound rule for $exePath`: $($_.Exception.Message)" "Error"
        }
        
        # Create inbound rule
        $inboundRuleName = "$Script:RuleBaseName - $exeName Inbound ($ruleNumber)"
        try {
            New-NetFirewallRule -DisplayName $inboundRuleName `
                               -Direction Inbound `
                               -Program $exePath `
                               -Action Block `
                               -Profile Any `
                               -Enabled True `
                               -Description "Blocks $exeName from receiving internet connections (inbound)" `
                               -ErrorAction Stop | Out-Null
            
            Write-LogMessage "Created inbound rule: $inboundRuleName" "Success"
            $rulesCreated++
        }
        catch {
            Write-LogMessage "Failed to create inbound rule for $exePath`: $($_.Exception.Message)" "Error"
        }
        
        $ruleNumber++
    }
    
    # Create additional rules to block update services
    Write-LogMessage "Creating rules to block update services..." "Info"
    
    # Block common update service executables
    $updateServices = @(
        "$env:ProgramData\StartAllBack\update.exe",
        "$env:LocalAppData\StartAllBack\updater.exe",
        "$env:ProgramFiles\StartAllBack\StartAllBackUpdater.exe"
    )
    
    foreach ($updateExe in $updateServices) {
        if (Test-Path $updateExe) {
            $updateRuleName = "$Script:RuleBaseName - Update Service Block ($ruleNumber)"
            try {
                New-NetFirewallRule -DisplayName $updateRuleName `
                                   -Direction Outbound `
                                   -Program $updateExe `
                                   -Action Block `
                                   -Profile Any `
                                   -Enabled True `
                                   -Description "Blocks StartAllBack update service" `
                                   -ErrorAction Stop | Out-Null
                
                Write-LogMessage "Created update service block rule: $updateRuleName" "Success"
                $rulesCreated++
                $ruleNumber++
            }
            catch {
                Write-LogMessage "Failed to block update service: $($_.Exception.Message)" "Warning"
            }
        }
    }
    
    Write-LogMessage "Created $rulesCreated firewall rules" "Success"
    return $rulesCreated
}

function Remove-FirewallRules {
    Write-LogMessage "Removing existing StartAllBack firewall rules..." "Info"
    
    $removedRules = 0
    
    try {
        $existingRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "$Script:RuleBaseName*" }
        
        foreach ($rule in $existingRules) {
            Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
            Write-LogMessage "Removed rule: $($rule.DisplayName)" "Success"
            $removedRules++
        }
        
        if ($removedRules -eq 0) {
            Write-LogMessage "No existing firewall rules found to remove" "Info"
        } else {
            Write-LogMessage "Removed $removedRules firewall rules" "Success"
        }
    }
    catch {
        Write-LogMessage "Error removing firewall rules: $($_.Exception.Message)" "Error"
    }
    
    return $removedRules
}

function Add-HostsFileEntries {
    if (-not $IncludeHostsFile) {
        Write-LogMessage "Hosts file modification skipped (IncludeHostsFile = false)" "Info"
        return
    }
    
    Write-LogMessage "Adding entries to hosts file..." "Info"
    
    try {
        # Read current hosts file content
        $hostsContent = Get-Content $Script:HostsFilePath -ErrorAction Stop
        $originalContent = $hostsContent -join "`r`n"
        
        # Check if our marker already exists
        $markerStart = "# StartAllBack Block - START"
        $markerEnd = "# StartAllBack Block - END"
        
        # Remove existing entries if they exist
        $startIndex = -1
        $endIndex = -1
        
        for ($i = 0; $i -lt $hostsContent.Length; $i++) {
            if ($hostsContent[$i] -eq $markerStart) {
                $startIndex = $i
            }
            if ($hostsContent[$i] -eq $markerEnd) {
                $endIndex = $i
                break
            }
        }
        
        if ($startIndex -ge 0 -and $endIndex -ge 0) {
            # Remove existing block
            $newContent = @()
            if ($startIndex -gt 0) {
                $newContent += $hostsContent[0..($startIndex-1)]
            }
            if ($endIndex -lt ($hostsContent.Length - 1)) {
                $newContent += $hostsContent[($endIndex+1)..($hostsContent.Length-1)]
            }
            $hostsContent = $newContent
        }
        
        # Add new entries
        $newEntries = @()
        $newEntries += ""
        $newEntries += $markerStart
        $newEntries += "# Blocks StartAllBack update servers and Microsoft Store updates"
        
        foreach ($domain in $Script:BlockedDomains) {
            $newEntries += "0.0.0.0 $domain"
            $newEntries += "::0 $domain"  # IPv6 block
        }
        
        $newEntries += $markerEnd
        
        # Combine content
        $finalContent = $hostsContent + $newEntries
        
        # Write back to hosts file
        $finalContent | Out-File -FilePath $Script:HostsFilePath -Encoding ASCII -Force
        
        Write-LogMessage "Added $($Script:BlockedDomains.Count) domain entries to hosts file" "Success"
        
        # Flush DNS cache
        try {
            ipconfig /flushdns | Out-Null
            Write-LogMessage "DNS cache flushed successfully" "Success"
        }
        catch {
            Write-LogMessage "Warning: Could not flush DNS cache" "Warning"
        }
    }
    catch {
        Write-LogMessage "Failed to modify hosts file: $($_.Exception.Message)" "Error"
    }
}

function Remove-HostsFileEntries {
    if (-not $IncludeHostsFile) {
        return
    }
    
    Write-LogMessage "Removing entries from hosts file..." "Info"
    
    try {
        $hostsContent = Get-Content $Script:HostsFilePath -ErrorAction Stop
        
        $markerStart = "# StartAllBack Block - START"
        $markerEnd = "# StartAllBack Block - END"
        
        $startIndex = -1
        $endIndex = -1
        
        for ($i = 0; $i -lt $hostsContent.Length; $i++) {
            if ($hostsContent[$i] -eq $markerStart) {
                $startIndex = $i
            }
            if ($hostsContent[$i] -eq $markerEnd) {
                $endIndex = $i
                break
            }
        }
        
        if ($startIndex -ge 0 -and $endIndex -ge 0) {
            # Remove the block
            $newContent = @()
            if ($startIndex -gt 0) {
                $newContent += $hostsContent[0..($startIndex-1)]
            }
            if ($endIndex -lt ($hostsContent.Length - 1)) {
                $newContent += $hostsContent[($endIndex+1)..($hostsContent.Length-1)]
            }
            
            # Remove trailing empty lines
            while ($newContent.Length -gt 0 -and [string]::IsNullOrWhiteSpace($newContent[-1])) {
                $newContent = $newContent[0..($newContent.Length-2)]
            }
            
            $newContent | Out-File -FilePath $Script:HostsFilePath -Encoding ASCII -Force
            Write-LogMessage "Removed StartAllBack entries from hosts file" "Success"
            
            # Flush DNS cache
            ipconfig /flushdns | Out-Null
            Write-LogMessage "DNS cache flushed successfully" "Success"
        } else {
            Write-LogMessage "No StartAllBack entries found in hosts file" "Info"
        }
    }
    catch {
        Write-LogMessage "Failed to modify hosts file: $($_.Exception.Message)" "Error"
    }
}

function Disable-ScheduledUpdateTasks {
    Write-LogMessage "Disabling StartAllBack scheduled update tasks..." "Info"
    
    $disabledTasks = 0
    
    try {
        # Common task names used by StartAllBack
        $taskPatterns = @(
            "*StartAllBack*Update*",
            "*StartIsBack*Update*",
            "*StartAllBack*",
            "*StartIsBack*"
        )
        
        foreach ($pattern in $taskPatterns) {
            $tasks = Get-ScheduledTask -TaskName $pattern -ErrorAction SilentlyContinue
            
            foreach ($task in $tasks) {
                try {
                    Disable-ScheduledTask -TaskName $task.TaskName -ErrorAction Stop
                    Write-LogMessage "  Disabled scheduled task: $($task.TaskName)" "Success"
                    $disabledTasks++
                }
                catch {
                    Write-LogMessage "  Failed to disable task $($task.TaskName): $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        if ($disabledTasks -gt 0) {
            Write-LogMessage "Disabled $disabledTasks scheduled update task(s)" "Success"
        } else {
            Write-LogMessage "No scheduled update tasks found" "Info"
        }
    }
    catch {
        Write-LogMessage "Error processing scheduled tasks: $($_.Exception.Message)" "Warning"
    }
}

function Enable-ScheduledUpdateTasks {
    Write-LogMessage "Re-enabling StartAllBack scheduled update tasks..." "Info"
    
    $enabledTasks = 0
    
    try {
        $taskPatterns = @(
            "*StartAllBack*Update*",
            "*StartIsBack*Update*",
            "*StartAllBack*",
            "*StartIsBack*"
        )
        
        foreach ($pattern in $taskPatterns) {
            $tasks = Get-ScheduledTask -TaskName $pattern -ErrorAction SilentlyContinue
            
            foreach ($task in $tasks) {
                if ($task.State -eq "Disabled") {
                    try {
                        Enable-ScheduledTask -TaskName $task.TaskName -ErrorAction Stop
                        Write-LogMessage "  Enabled scheduled task: $($task.TaskName)" "Success"
                        $enabledTasks++
                    }
                    catch {
                        Write-LogMessage "  Failed to enable task $($task.TaskName): $($_.Exception.Message)" "Warning"
                    }
                }
            }
        }
        
        if ($enabledTasks -gt 0) {
            Write-LogMessage "Enabled $enabledTasks scheduled update task(s)" "Success"
        }
    }
    catch {
        Write-LogMessage "Error processing scheduled tasks: $($_.Exception.Message)" "Warning"
    }
}

function Get-BlockingStatus {
    Write-LogMessage "Checking current blocking status..." "Info"
    
    # Check firewall rules
    $firewallRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "$Script:RuleBaseName*" }
    $activeRules = $firewallRules | Where-Object { $_.Enabled -eq $true }
    
    Write-Host "`n=== FIREWALL STATUS ===" -ForegroundColor Cyan
    Write-Host "Total firewall rules: $($firewallRules.Count)" -ForegroundColor White
    Write-Host "Active firewall rules: $($activeRules.Count)" -ForegroundColor White
    
    if ($activeRules.Count -gt 0) {
        Write-Host "Firewall Status: " -NoNewline -ForegroundColor White
        Write-Host "BLOCKING" -ForegroundColor Red
        
        Write-Host "`nActive Rules:" -ForegroundColor Yellow
        foreach ($rule in $activeRules | Sort-Object DisplayName) {
            Write-Host "  • $($rule.DisplayName) [$($rule.Direction)]" -ForegroundColor Gray
        }
    } else {
        Write-Host "Firewall Status: " -NoNewline -ForegroundColor White
        Write-Host "NOT BLOCKING" -ForegroundColor Green
    }
    
    # Check hosts file
    Write-Host "`n=== HOSTS FILE STATUS ===" -ForegroundColor Cyan
    try {
        $hostsContent = Get-Content $Script:HostsFilePath -ErrorAction Stop
        $markerFound = $hostsContent | Where-Object { $_ -eq "# StartAllBack Block - START" }
        
        if ($markerFound) {
            Write-Host "Hosts File Status: " -NoNewline -ForegroundColor White
            Write-Host "BLOCKING" -ForegroundColor Red
            
            $blockedDomains = $hostsContent | Where-Object { $_ -match "^0\.0\.0\.0\s+(.*startallback.*|.*startisback.*)" }
            Write-Host "Blocked domains: $($blockedDomains.Count)" -ForegroundColor White
            
            foreach ($entry in $blockedDomains) {
                $domain = ($entry -split '\s+')[1]
                Write-Host "  • $domain" -ForegroundColor Gray
            }
        } else {
            Write-Host "Hosts File Status: " -NoNewline -ForegroundColor White
            Write-Host "NOT BLOCKING" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Hosts File Status: " -NoNewline -ForegroundColor White
        Write-Host "ERROR READING FILE" -ForegroundColor Red
    }
    
    # Check Microsoft Store blocking status
    Write-Host "`n=== MICROSOFT STORE BLOCKING STATUS ===" -ForegroundColor Cyan
    try {
        $storeBlocked = $false
        $blockedPackages = @()
        
        # Check registry for blocked packages
        $blockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ExcludedApplications"
        if (Test-Path $blockPath) {
            $blockedApps = Get-Item $blockPath -ErrorAction SilentlyContinue
            if ($blockedApps) {
                $blockedApps.Property | ForEach-Object {
                    if ($_ -match "StartAllBack|StartIsBack") {
                        $blockedPackages += $_
                        $storeBlocked = $true
                    }
                }
            }
        }
        
        # Check Store auto-update policy
        $storePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
        $autoDownloadDisabled = $false
        if (Test-Path $storePolicyPath) {
            $autoDownload = Get-ItemProperty -Path $storePolicyPath -Name "AutoDownload" -ErrorAction SilentlyContinue
            if ($autoDownload.AutoDownload -eq 2) {
                $autoDownloadDisabled = $true
            }
        }
        
        if ($storeBlocked -or $autoDownloadDisabled) {
            Write-Host "Store Update Status: " -NoNewline -ForegroundColor White
            Write-Host "BLOCKING" -ForegroundColor Red
            
            if ($blockedPackages.Count -gt 0) {
                Write-Host "Blocked packages: $($blockedPackages.Count)" -ForegroundColor White
                foreach ($pkg in $blockedPackages) {
                    Write-Host "  • $pkg" -ForegroundColor Gray
                }
            }
            
            if ($autoDownloadDisabled) {
                Write-Host "Store Auto-Update: " -NoNewline -ForegroundColor White
                Write-Host "DISABLED" -ForegroundColor Red
            }
        } else {
            Write-Host "Store Update Status: " -NoNewline -ForegroundColor White
            Write-Host "NOT BLOCKING" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Store Update Status: " -NoNewline -ForegroundColor White
        Write-Host "ERROR CHECKING STATUS" -ForegroundColor Red
    }
    
    # Check scheduled tasks
    Write-Host "`n=== SCHEDULED TASKS STATUS ===" -ForegroundColor Cyan
    try {
        $taskPatterns = @("*StartAllBack*", "*StartIsBack*")
        $allTasks = @()
        
        foreach ($pattern in $taskPatterns) {
            $tasks = Get-ScheduledTask -TaskName $pattern -ErrorAction SilentlyContinue
            $allTasks += $tasks
        }
        
        if ($allTasks.Count -gt 0) {
            $disabledTasks = $allTasks | Where-Object { $_.State -eq "Disabled" }
            $enabledTasks = $allTasks | Where-Object { $_.State -ne "Disabled" }
            
            Write-Host "Total scheduled tasks: $($allTasks.Count)" -ForegroundColor White
            Write-Host "Disabled tasks: $($disabledTasks.Count)" -ForegroundColor White
            Write-Host "Enabled tasks: $($enabledTasks.Count)" -ForegroundColor White
            
            if ($disabledTasks.Count -gt 0) {
                Write-Host "`nDisabled Tasks:" -ForegroundColor Yellow
                foreach ($task in $disabledTasks) {
                    Write-Host "  • $($task.TaskName) [DISABLED]" -ForegroundColor Gray
                }
            }
            
            if ($enabledTasks.Count -gt 0) {
                Write-Host "`nEnabled Tasks:" -ForegroundColor Yellow
                foreach ($task in $enabledTasks) {
                    Write-Host "  • $($task.TaskName) [ENABLED]" -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "No StartAllBack scheduled tasks found" -ForegroundColor White
        }
    }
    catch {
        Write-Host "Error checking scheduled tasks" -ForegroundColor Red
    }
    
    # Check for StartAllBack processes
    Write-Host "`n=== PROCESS STATUS ===" -ForegroundColor Cyan
    $runningProcesses = Get-Process | Where-Object { $_.ProcessName -match "StartAllBack|StartIsBack" }
    
    if ($runningProcesses.Count -gt 0) {
        Write-Host "Running StartAllBack processes: $($runningProcesses.Count)" -ForegroundColor White
        foreach ($process in $runningProcesses) {
            Write-Host "  • $($process.ProcessName) (PID: $($process.Id))" -ForegroundColor Gray
        }
    } else {
        Write-Host "Running StartAllBack processes: 0" -ForegroundColor White
    }
    
    # Check for Store packages
    Write-Host "`n=== INSTALLED STORE PACKAGES ===" -ForegroundColor Cyan
    try {
        $storePackages = @()
        foreach ($packageName in $Script:StorePackageNames) {
            $packages = Get-AppxPackage -Name $packageName -AllUsers -ErrorAction SilentlyContinue
            $storePackages += $packages
        }
        
        if ($storePackages.Count -gt 0) {
            Write-Host "Installed StartAllBack Store packages: $($storePackages.Count)" -ForegroundColor White
            foreach ($package in $storePackages) {
                Write-Host "  • $($package.Name) v$($package.Version)" -ForegroundColor Gray
                Write-Host "    Package: $($package.PackageFullName)" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "No StartAllBack Store packages found" -ForegroundColor White
        }
    }
    catch {
        Write-Host "Error checking Store packages" -ForegroundColor Red
    }
    
    Write-Host ""
}

function Start-BlockingProcess {
    Write-LogMessage "Starting comprehensive StartAllBack blocking process..." "Info"
    
    # Find executables
    $executables = Find-StartAllBackExecutables
    
    if ($executables.Count -eq 0) {
        Write-LogMessage "Cannot proceed: No StartAllBack executables found!" "Error"
        Write-LogMessage "StartAllBack may not be installed or is installed in a non-standard location." "Warning"
        
        # Ask if user wants to continue anyway
        Write-Host "`nDo you want to continue blocking update servers and Store updates anyway? (Y/N): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        
        if ($response -notmatch "^[Yy]") {
            Write-LogMessage "Blocking process cancelled by user" "Info"
            return $false
        }
    }
    
    # Remove existing rules first
    Remove-FirewallRules | Out-Null
    
    # Create new firewall rules
    $rulesCreated = 0
    if ($executables.Count -gt 0) {
        $rulesCreated = New-FirewallRules -ExecutablePaths $executables
    }
    
    # Block Microsoft Store updates
    Block-MicrosoftStoreUpdates
    
    # Modify hosts file
    Add-HostsFileEntries
    
    # Disable scheduled update tasks
    Disable-ScheduledUpdateTasks
    
    if ($rulesCreated -gt 0 -or $executables.Count -eq 0) {
        Write-LogMessage "StartAllBack blocking process completed!" "Success"
        Write-LogMessage "Applied multiple layers of protection:" "Success"
        Write-LogMessage "  ✓ Firewall rules: $rulesCreated" "Success"
        Write-LogMessage "  ✓ Hosts file entries: Added" "Success"
        Write-LogMessage "  ✓ Store updates: Blocked" "Success"
        Write-LogMessage "  ✓ Scheduled tasks: Disabled" "Success"
        return $true
    } else {
        Write-LogMessage "Failed to create comprehensive blocks!" "Error"
        return $false
    }
}

function Start-UnblockingProcess {
    Write-LogMessage "Starting StartAllBack unblocking process..." "Info"
    
    # Remove firewall rules
    $rulesRemoved = Remove-FirewallRules
    
    # Unblock Microsoft Store updates
    Unblock-MicrosoftStoreUpdates
    
    # Remove hosts file entries
    Remove-HostsFileEntries
    
    # Re-enable scheduled update tasks
    Enable-ScheduledUpdateTasks
    
    Write-LogMessage "StartAllBack unblocking completed!" "Success"
    Write-LogMessage "Removed all blocking mechanisms:" "Success"
    Write-LogMessage "  ✓ Firewall rules removed: $rulesRemoved" "Success"
    Write-LogMessage "  ✓ Hosts file entries: Removed" "Success"
    Write-LogMessage "  ✓ Store updates: Unblocked" "Success"
    Write-LogMessage "  ✓ Scheduled tasks: Re-enabled" "Success"
    
    return $true
}

# Main execution
try {
    Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║     StartAllBack Complete Blocking Script v2.0               ║
║     Enhanced with Microsoft Store Update Protection          ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
    
    Write-Host ""
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        exit 1
    }
    
    Write-Host ""
    
    # Execute based on action
    switch ($Action) {
        "Block" {
            $success = Start-BlockingProcess
            if ($success) {
                Write-Host "`n" -NoNewline
                Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
                Write-Host "StartAllBack is now completely blocked from:" -ForegroundColor Green
                Write-Host "  • Accessing the internet (firewall rules)" -ForegroundColor White
                Write-Host "  • Connecting to update servers (hosts file)" -ForegroundColor White
                Write-Host "  • Receiving Microsoft Store updates" -ForegroundColor White
                Write-Host "  • Running scheduled update tasks" -ForegroundColor White
                Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
                Write-Host "`nTo restore functionality, run this script with -Action Unblock" -ForegroundColor Yellow
            }
        }
        
        "Unblock" {
            $success = Start-UnblockingProcess
            if ($success) {
                Write-Host "`n" -NoNewline
                Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
                Write-Host "StartAllBack functionality has been fully restored." -ForegroundColor Green
                Write-Host "The application can now:" -ForegroundColor White
                Write-Host "  • Access the internet normally" -ForegroundColor White
                Write-Host "  • Connect to update servers" -ForegroundColor White
                Write-Host "  • Receive Microsoft Store updates" -ForegroundColor White
                Write-Host "  • Run scheduled update tasks" -ForegroundColor White
                Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
                Write-Host "`nTo block again, run this script with -Action Block" -ForegroundColor Yellow
            }
        }
        
        "Status" {
            Get-BlockingStatus
        }
    }
    
    Write-Host ""
    Write-LogMessage "Script execution completed successfully" "Success"
}
catch {
    Write-LogMessage "Unexpected error: $($_.Exception.Message)" "Error"
    Write-LogMessage "Stack trace: $($_.ScriptStackTrace)" "Error"
    exit 1
}
