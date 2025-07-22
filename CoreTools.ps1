# This script sets the PowerShell execution policy and then executes a child PowerShell script and configures custom right-click menus in the Registry.

# Sets the PowerShell execution policy for the current user to 'Unrestricted'.
# This allows all PowerShell scripts to run on the system without restrictions.
# -Scope CurrentUser: Applies the change only to the current user.
# -Unrestricted: Allows all script files to run.
# -Force: Suppresses the confirmation prompt.
Write-Host "Setting PowerShell execution policy to Unrestricted for the current user..."
Set-ExecutionPolicy -Scope CurrentUser Unrestricted -Force >$null 2>&1

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

# --- 4. Software Installations via Chocolatey ---
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
    "element-desktop"
    "audacity"
    "lightshot"
    "hashcheck"
    "openhashtab"
    "jami"
    "sd-card-formatter"
    "veracrypt"
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
Write-Host "Reverting PowerShell execution policy to RemoteSigned for current user..."
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force >$null 2>&1
Write-Host "Execution policy set to RemoteSigned for current user."

Write-Host "Software setup and installation completed successfully! ✅"
