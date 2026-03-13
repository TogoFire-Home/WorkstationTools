# This script sets the PowerShell execution policy and then executes a child PowerShell script and configures custom right-click menus in the Registry.

# Sets the PowerShell execution policy for the current user to 'Unrestricted'.
# This allows all PowerShell scripts to run on the system without restrictions.
# -Scope CurrentUser: Applies the change only to the current user.
# -Unrestricted: Allows all script files to run.
# -Force: Suppresses the confirmation prompt.
# Write-Host "Setting PowerShell execution policy to Unrestricted for the current user..."
# Set-ExecutionPolicy -Scope CurrentUser Unrestricted -Force >$null 2>&1

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

# --- Registry configuration ---
# Define entries for Command Prompt custom menus
$cmdEntries = @(
    @{
        Path = "HKEY_CLASSES_ROOT\Directory\shell\01MenuCmd"
        Values = @{
            "MUIVerb" = "Command Prompts"
            "Icon" = "cmd.exe"
            "ExtendedSubCommandsKey" = "Directory\ContextMenus\MenuCmd"
            "Extended" = "" # This makes this menu appear only with Shift+Right-Click
        }
    },
    @{
        Path = "HKEY_CLASSES_ROOT\Directory\background\shell\01MenuCmd"
        Values = @{
            "MUIVerb" = "Command Prompts"
            "Icon" = "cmd.exe"
            "ExtendedSubCommandsKey" = "Directory\ContextMenus\MenuCmd"
            "Extended" = "" # This makes this menu appear only with Shift+Right-Click
        }
    },
    @{
        Path = "HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuCmd\shell\open"
        Values = @{
            "MUIVerb" = "Command Prompt"
            "Icon" = "cmd.exe"
        }
    },
    @{
        Path = "HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuCmd\shell\open\command"
        Values = @{
            # cmd.exe
            "(Default)" = 'cmd.exe /s /k pushd "%V"'
        }
    },
    @{
        Path = "HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuCmd\shell\runas"
        Values = @{
            "MUIVerb" = "Command Prompt Elevated"
            "Icon" = "cmd.exe"
            "HasLUAShield" = ""
        }
    },
    @{
        Path = "HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuCmd\shell\runas\command"
        Values = @{
            # cmd.exe
            "(Default)" = 'cmd.exe /s /k pushd "%V"'
        }
    }
)

# Define entries for PowerShell custom menus
$psEntries = @(
    @{
        Path = "HKEY_CLASSES_ROOT\Directory\shell\02MenuPowerShell"
        Values = @{
            "MUIVerb" = "PowerShell Prompts"
            "Icon" = "powershell.exe"
            "ExtendedSubCommandsKey" = "Directory\ContextMenus\MenuPowerShell"
            "Extended" = "" # This makes this menu appear only with Shift+Right-Click
        }
    },
    @{
        Path = "HKEY_CLASSES_ROOT\Directory\background\shell\02MenuPowerShell"
        Values = @{
            "MUIVerb" = "PowerShell Prompts"
            "Icon" = "powershell.exe"
            "ExtendedSubCommandsKey" = "Directory\ContextMenus\MenuPowerShell"
            "Extended" = "" # This makes this menu appear only with Shift+Right-Click
        }
    },
    @{
        Path = "HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPowerShell\shell\open"
        Values = @{
            "MUIVerb" = "PowerShell"
            "Icon" = "powershell.exe"
        }
    },
    @{
        Path = "HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPowerShell\shell\open\command"
        Values = @{
            # PowerShell path handling
            "(Default)" = 'powershell.exe -noexit -command Set-Location ''%V'''
        }
    },
    @{
        Path = "HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPowerShell\shell\runas"
        Values = @{
            "MUIVerb" = "PowerShell Elevated"
            "Icon" = "powershell.exe"
            "HasLUAShield" = ""
        }
    },
    @{
        Path = "HKEY_CLASSES_ROOT\Directory\ContextMenus\MenuPowerShell\shell\runas\command"
        Values = @{
            # PowerShell path handling
            "(Default)" = 'powershell.exe -noexit -command Set-Location ''%V'''
        }
    }
)

# The extendedEntries array is now empty and will no longer be passed to Set-RegistryEntries.
$extendedEntries = @()

## Registry Function

# Function to create keys and set values
function Set-RegistryEntries {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Entries
    )

    foreach ($entry in $Entries) {
        $path = $entry.Path
        $values = $entry.Values

        Write-Host "Processing key: $path"

        # --- Ensure all parent keys exist ---
        # Split the path into components (e.g., HKEY_CLASSES_ROOT, Directory, ContextMenus, etc.)
        # The first component (e.g., HKEY_CLASSES_ROOT) is the root and doesn't need creation.
        $pathComponents = $path.Split('\')
        $currentPath = $pathComponents[0] # Start with the root, e.g., HKEY_CLASSES_ROOT

        # Iterate through the components, creating each part of the path if it doesn't exist
        for ($i = 1; $i -lt $pathComponents.Length; $i++) {
            $currentPath = "$currentPath\$($pathComponents[$i])"
            Try {
                if (-not (Test-Path "Registry::$currentPath")) {
                    New-Item -Path "Registry::$currentPath" -ErrorAction Stop | Out-Null
                    Write-Host "Created parent key: $currentPath"
                }
            }
            Catch [System.Management.Automation.DriveNotFoundException] {
                Write-Error "Error: Could not create parent key '$currentPath'. Ensure you are running PowerShell as Administrator and the path is valid. $($_.Exception.Message)"
                # Stop processing this entry if a parent key cannot be created
                continue
            }
            Catch {
                Write-Error "An unexpected error occurred while creating/checking parent key '$currentPath': $($_.Exception.Message)"
                # Stop processing this entry if a parent key cannot be created
                continue
            }
        }
        # --- End Ensure ---

        # Now that all parent keys are guaranteed to exist, create the final key if it doesn't.
        Try {
            if (-not (Test-Path "Registry::$path")) {
                New-Item -Path "Registry::$path" -ErrorAction Stop | Out-Null
                Write-Host "Key created: $path"
            } else {
                Write-Host "Key already exists: $path"
            }
        }
        Catch [System.Management.Automation.DriveNotFoundException] {
            Write-Error "Error: Could not create key '$path'. Ensure you are running PowerShell as Administrator and the path is valid. $($_.Exception.Message)"
            continue
        }
        Catch {
            Write-Error "An unexpected error occurred while creating/checking key '$path': $($_.Exception.Message)"
            continue
        }

        # Set the values
        foreach ($key in $values.Keys) {
            $value = $values[$key]
            Try {
                if ($key -eq "(Default)") {
                    Set-ItemProperty -LiteralPath "Registry::$path" -Name "(Default)" -Value $value -Force -ErrorAction Stop
                    Write-Host "Set default value to '$value' in $path"
                } else {
                    Set-ItemProperty -LiteralPath "Registry::$path" -Name $key -Value $value -Force -ErrorAction Stop
                    Write-Host "Set value '$key' = '$value' in $path"
                }
            }
            Catch [System.Management.Automation.DriveNotFoundException] {
                Write-Error "Error: Could not set property '$key' in '$path'. Ensure you are running PowerShell as Administrator and the path is valid. $($_.Exception.Message)"
            }
            Catch {
                Write-Error "An unexpected error occurred while setting property '$key' in '$path': $($_.Exception.Message)"
            }
        }
    }
}

## Script Execution

Write-Host "Starting Registry configuration for Command Prompt and PowerShell..."

# Execute Command Prompt configurations
Set-RegistryEntries -Entries $cmdEntries

# Execute PowerShell configurations
Set-RegistryEntries -Entries $psEntries

Write-Host "Registry configuration completed successfully! 🎉"

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
Write-Host "Hiding Recycle Bin from Desktop..."
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 1 -PropertyType DWord -Force

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

# --- 10. Context Menu: Restore ShellNew for Scripts (.bat, .ps1, .reg, .vbs) ---
Write-Host "Restoring Scripting ShellNew Menu Items..."
New-Item -Path 'HKCR:\.vbs\ShellNew','HKCR:\.bat\ShellNew','HKCR:\.cmd\ShellNew','HKCR:\.reg\ShellNew','HKCR:\.ps1\ShellNew' -Force | Out-Null
Set-ItemProperty -Path 'HKCR:\.vbs\ShellNew' -Name 'NullFile' -Value ''
Set-ItemProperty -Path 'HKCR:\.bat\ShellNew' -Name 'NullFile' -Value ''
Set-ItemProperty -Path 'HKCR:\.cmd\ShellNew' -Name 'NullFile' -Value ''
Set-ItemProperty -Path 'HKCR:\.reg\ShellNew' -Name 'NullFile' -Value ''
Set-ItemProperty -Path 'HKCR:\.ps1\ShellNew' -Name 'NullFile' -Value ''

# --- 11. Context Menu: Add 'Check File Ownership' (Strict Check) ---

# Get the ReleaseId or DisplayVersion (this is where "25H2" is stored)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$releaseVersion = (Get-ItemProperty -Path $regPath -Name "DisplayVersion").DisplayVersion

# Apply configuration ONLY if version is NOT "25H2" and is "26H1" or higher
# We check if the version is specifically NOT 25H2
if ($releaseVersion -ne "25H2") {
    $cmd = 'powershell.exe -NoExit -Command "$owner = (Get-ChildItem ''%1'' -Force).GetAccessControl().Owner; Write-Host \"Owner : $owner\""'
    $keys = @(
        'HKCU:\Software\Classes\*\shell\Owner\command', 
        'HKCU:\Software\Classes\Directory\shell\Owner\command', 
        'HKCU:\Software\Classes\Drive\shell\Owner\command'
    )
    
    foreach ($k in $keys) { 
        if (!(Test-Path $k)) { 
            New-Item -Path $k -Force | Out-Null 
        }
        Set-Item -Path $k -Value $cmd -Force 
    }
    Write-Host "Context Menu 'Owner' check configured successfully." -ForegroundColor Green
} else {
    Write-Host "Detected version $releaseVersion. Skipping configuration (Only for 26H1+)." -ForegroundColor Yellow
}

# --- 12. Disable Network Access in Modern Standby ---
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

# --- Refresh System ---
Write-Host "Restarting Explorer to apply changes..."
Stop-Process -Name explorer -Force
Write-Host "`nConfiguration Completed Successfully! ✅" -ForegroundColor Green

##------------------------------------------------------##

# --- Function to check if a command exists ---
function Test-CommandExists {
    param(
        [string]$Command
    )
    (Get-Command -Name $Command -ErrorAction SilentlyContinue) -ne $null
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

# --- 4 Optional Category with 5-second Timeout ---
$optionalPackages = @("git", "qbittorrent-enhanced", "veracrypt", "element-desktop")
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
    "hashcheck"
    "openhashtab"
    "jami"
    "sd-card-formatter"
    "th-ch-youtube-music"
    "winscp.install"
    "zstandard"
    "wiresockvpnclient"
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

# --- 6. Revert Execution Policy to RemoteSigned for CurrentUser ---
#Write-Host "Reverting PowerShell execution policy to RemoteSigned for current user..."
#Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force >$null 2>&1
#Write-Host "Execution policy set to RemoteSigned for current user."
#Write-Host "Software setup and installation completed successfully! ✅"
