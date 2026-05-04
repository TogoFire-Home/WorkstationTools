#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# ============================================================
# SIMPLE POWER PLAN MANAGER DEPLOYMENT
# ============================================================

Write-Host "[MODULE] Deploying Simple Power Plan Manager via dynamic GitHub resolution..." -ForegroundColor Cyan

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$installDir    = "C:\Program Files\Tools\Apps\Simple Power Plan Manager"
$versionMarker = "$env:APPDATA\SimplePowerPlanManager\versionsp.txt"
$exeName       = "Simple_power_plan_manager.exe"
$exePath       = Join-Path $installDir $exeName
$tempExe       = Join-Path $env:TEMP $exeName
$shortcutPath  = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Simple Power Plan Manager.lnk"
$ua            = "Mozilla/5.0"
$skipInstall   = $false

try {
    # ------------------------------------------------------------
    # FETCH LATEST VERSION FROM GITHUB API
    # ------------------------------------------------------------
    Write-Host ">> Resolving latest version from GitHub... " -ForegroundColor Yellow -NoNewline

    $apiUrl = "https://api.github.com/repos/fpsheaven/Simple-Power-Plan-Manager/releases/latest"
    $headers = @{ "User-Agent" = $ua }
    $latestVersion = $null
    $latestVersionStr = $null

    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -ErrorAction Stop
        $latestVersionStr = $response.tag_name -replace '^[vV]', ''
        $latestVersion = [version]$latestVersionStr
        Write-Host "[OK: v$latestVersionStr]" -ForegroundColor Green
    }
    catch {
        try {
            $repoUrl = "https://github.com/fpsheaven/Simple-Power-Plan-Manager"
            $html = Invoke-WebRequest -Uri "$repoUrl/releases" -Headers $headers -UseBasicParsing -ErrorAction Stop

            if ($html.Content -match "/releases/tag/(?:v|V)?([\d\.]+)") {
                $latestVersionStr = $matches[1]
                $latestVersion = [version]$latestVersionStr
                Write-Host "[OK: v$latestVersionStr]" -ForegroundColor Green
            }
            else {
                Write-Host "[VERSION NOT FOUND - SKIPPING MODULE]" -ForegroundColor Red
                $skipInstall = $true
            }
        }
        catch {
            Write-Host "[VERSION LOOKUP FAILED - SKIPPING MODULE]" -ForegroundColor Red
            $skipInstall = $true
        }
    }

    if (-not $skipInstall) {
        # ------------------------------------------------------------
        # DETECT CURRENT INSTALLED VERSION
        # ------------------------------------------------------------
        Write-Host ">> Checking local version marker..." -ForegroundColor Yellow

        $currentVersion = [version]"0.0.0.0"
        $detected = $false

        if (Test-Path -Path $versionMarker) {
            try {
                $content = (Get-Content -Path $versionMarker -Raw -ErrorAction Stop).Trim()

                if ($content -match "^([\d\.]+)$") {
                    $currentVersion = [version]$matches[1]
                    $detected = $true
                    Write-Host "   [VERSION FOUND] Installed: $currentVersion" -ForegroundColor Cyan
                }
            }
            catch {
                Write-Host "   [READ FAILED]" -ForegroundColor DarkYellow
            }
        }

        if (-not $detected) {
            Write-Host "   [NO PREVIOUS VERSION MARKER]" -ForegroundColor DarkGray
        }

        # ------------------------------------------------------------
        # VERSION COMPARISON
        # ------------------------------------------------------------
        if ($latestVersion -le $currentVersion -and (Test-Path -Path $exePath)) {
            Write-Host ">> Status: [ALREADY UP TO DATE]" -ForegroundColor Green
            $skipInstall = $true
        }

        # ------------------------------------------------------------
        # DOWNLOAD & DEPLOYMENT
        # ------------------------------------------------------------
        if (-not $skipInstall) {
            Write-Host ">> Status: [UPDATE REQUIRED]" -ForegroundColor Cyan

            $downloadUrl = "https://github.com/fpsheaven/Simple-Power-Plan-Manager/releases/download/v$latestVersionStr/$exeName"

            Write-Host ">> Downloading $exeName... " -ForegroundColor Yellow -NoNewline
            Invoke-WebRequest -Uri $downloadUrl -OutFile $tempExe -UserAgent $ua -ErrorAction Stop
            Write-Host "[OK]" -ForegroundColor Green

            if (-not (Test-Path -Path $installDir)) {
                New-Item -Path $installDir -ItemType Directory -Force | Out-Null
            }

            $versionMarkerDir = Split-Path -Path $versionMarker -Parent

            if (-not (Test-Path -Path $versionMarkerDir)) {
                New-Item -Path $versionMarkerDir -ItemType Directory -Force | Out-Null
            }

            Move-Item -Path $tempExe -Destination $exePath -Force

            Set-Content -Path $versionMarker -Value $latestVersionStr -Force
            Write-Host ">> Version marker updated to: $latestVersionStr" -ForegroundColor Gray

            # ------------------------------------------------------------
            # CREATE START MENU SHORTCUT
            # ------------------------------------------------------------
            Write-Host ">> Creating Start Menu shortcut... " -ForegroundColor Yellow -NoNewline

            if (Test-Path -Path $exePath) {
                $WshShell = New-Object -ComObject WScript.Shell
                $shortcut = $WshShell.CreateShortcut($shortcutPath)
                $shortcut.TargetPath = $exePath
                $shortcut.WorkingDirectory = $installDir
                $shortcut.Save()

                Write-Host "[OK]" -ForegroundColor Green
            }
            else {
                Write-Host "[EXECUTABLE NOT FOUND]" -ForegroundColor Red
            }

            Write-Host ">> Deployment completed successfully." -ForegroundColor Green
        }
    }
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    if (-not [string]::IsNullOrEmpty($tempExe) -and (Test-Path -Path $tempExe)) {
        Remove-Item -Path $tempExe -Force -ErrorAction SilentlyContinue
    }
}


# ============================================================
# POWER PLAN DOWNLOADER & INSTALLER
# ============================================================

$ErrorActionPreference = "Stop"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RepoUser       = "TogoFire-Home"
$RepoName       = "WorkstationTools"
$Branch         = "main"
$SubPath        = "Tools/System/PowerPlans"

$TargetDir      = "$env:ProgramFiles\Tools\System\PowerPlans"
$StateDir       = Join-Path $TargetDir "ImportedPlans"
$UserAgent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
$ApiUrl         = "https://api.github.com/repos/$RepoUser/$RepoName/contents/${SubPath}?ref=$Branch"
$RawBaseUrl     = "https://raw.githubusercontent.com/$RepoUser/$RepoName/$Branch/$SubPath"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   Power Plans Downloader & Installer   " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

try {
    # ------------------------------------------------------------
    # PREPARE DIRECTORIES
    # ------------------------------------------------------------
    if (-not (Test-Path -LiteralPath $TargetDir)) {
        New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null
    }

    if (-not (Test-Path -LiteralPath $StateDir)) {
        New-Item -Path $StateDir -ItemType Directory -Force | Out-Null
    }

    # ------------------------------------------------------------
    # FETCH REPOSITORY FILE LIST
    # ------------------------------------------------------------
    Write-Host ">> Fetching power plan list from GitHub..." -ForegroundColor Yellow

    $repoContents = Invoke-RestMethod -Uri $ApiUrl -Headers @{
        "User-Agent" = $UserAgent
    } -ErrorAction Stop

    $PowerFiles = @(
        $repoContents |
            Where-Object {
                $_.type -eq "file" -and $_.name -like "*.pow"
            } |
            Select-Object -ExpandProperty name
    )

    if ($PowerFiles.Count -eq 0) {
        throw "No .pow files were found in the repository."
    }

    Write-Host "[OK] Found $($PowerFiles.Count) power plan files." -ForegroundColor Green

    # ------------------------------------------------------------
    # READ CURRENT WINDOWS POWER PLANS
    # ------------------------------------------------------------
    Write-Host ">> Detecting existing Windows power plans..." -ForegroundColor Yellow

    $powercfgOutput = & powercfg.exe /list 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "Unable to query existing power plans with powercfg /list."
    }

    $ExistingGuids = @(
        foreach ($line in $powercfgOutput) {
            if ("$line" -match '\b([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})\b') {
                $matches[1].ToLowerInvariant()
            }
        }
    )

    $ExistingNames = @(
        foreach ($line in $powercfgOutput) {
            if ("$line" -match ':\s*(.+?)\s*(?:\(([0-9a-fA-F-]{36})\))?\s*$') {
                $matches[1].Trim()
            }
        }
    )

    # Normalize names for approximate filename/display-name matching.
    $NormalizeName = {
        param([string]$Name)

        return (($Name -replace '\.pow$', '') -replace '[^a-zA-Z0-9]', '').ToLowerInvariant()
    }

    # ------------------------------------------------------------
    # PROCESS EACH POWER PLAN INDIVIDUALLY
    # ------------------------------------------------------------
    $ImportedCount = 0
    $SkippedCount  = 0
    $FailedCount   = 0

    foreach ($file in $PowerFiles) {
        $stateName = [System.IO.Path]::GetFileNameWithoutExtension($file)
        $stateKey = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData(
                [System.Text.Encoding]::UTF8.GetBytes($file)
            )
        ).Substring(0, 16).ToLowerInvariant()

        $stateFile = Join-Path $StateDir "$stateKey.json"
        $localPath = Join-Path $TargetDir $file
        $normalizedFileName = & $NormalizeName $stateName

        # --------------------------------------------------------
        # CHECK PREVIOUSLY RECORDED PLAN GUID
        # --------------------------------------------------------
        $RecordedGuid = $null

        if (Test-Path -LiteralPath $stateFile) {
            try {
                $state = Get-Content -LiteralPath $stateFile -Raw |
                    ConvertFrom-Json -ErrorAction Stop

                $RecordedGuid = [string]$state.Guid
            }
            catch {
                $RecordedGuid = $null
            }
        }

        if (
            $RecordedGuid -and
            $ExistingGuids -contains $RecordedGuid.ToLowerInvariant()
        ) {
            Write-Host ">> Skipping $file (already installed)." -ForegroundColor DarkGray
            $SkippedCount++
            continue
        }

        # --------------------------------------------------------
        # CHECK EXISTING PLAN NAMES
        # --------------------------------------------------------
        $NameAlreadyExists = $false

        foreach ($existingName in $ExistingNames) {
            $normalizedExistingName = & $NormalizeName $existingName

            if (
                $normalizedFileName.Length -ge 8 -and
                $normalizedExistingName -eq $normalizedFileName
            ) {
                $NameAlreadyExists = $true
                break
            }
        }

        if ($NameAlreadyExists) {
            Write-Host ">> Skipping $file (matching plan name already exists)." -ForegroundColor DarkGray
            $SkippedCount++
            continue
        }

        # --------------------------------------------------------
        # DOWNLOAD POWER PLAN
        # --------------------------------------------------------
        $encodedFile = [System.Uri]::EscapeDataString($file)
        $fileUrl = "$RawBaseUrl/$encodedFile"

        Write-Host ">> Downloading $file..." -NoNewline -ForegroundColor Yellow

        try {
            Invoke-WebRequest -Uri $fileUrl -OutFile $localPath -Headers @{
                "User-Agent" = $UserAgent
            } -ErrorAction Stop

            Write-Host " [OK]" -ForegroundColor Green
        }
        catch {
            Write-Host " [FAILED]" -ForegroundColor Red
            Write-Host "   $($_.Exception.Message)" -ForegroundColor DarkYellow
            $FailedCount++
            continue
        }

        # --------------------------------------------------------
        # IMPORT ONLY THIS POWER PLAN
        # --------------------------------------------------------
        Write-Host ">> Importing $file..." -ForegroundColor Yellow

        $importOutput = & powercfg.exe /import "$localPath" 2>&1
        $importExitCode = $LASTEXITCODE

        if ($importExitCode -ne 0) {
            Write-Host "   [IMPORT FAILED]" -ForegroundColor Red
            Write-Host "   $($importOutput -join ' ')" -ForegroundColor DarkYellow
            $FailedCount++
            continue
        }

        # Refresh installed plan GUIDs after importing.
        $updatedOutput = & powercfg.exe /list 2>&1

        $UpdatedGuids = @(
            foreach ($line in $updatedOutput) {
                if ("$line" -match '\b([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})\b') {
                    $matches[1].ToLowerInvariant()
                }
            }
        )

        $NewGuids = @(
            $UpdatedGuids | Where-Object {
                $ExistingGuids -notcontains $_
            }
        )

        if ($NewGuids.Count -gt 0) {
            $newGuid = $NewGuids[-1]

            @{
                File = $file
                Guid = $newGuid
            } | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding UTF8

            $ExistingGuids = $UpdatedGuids

            Write-Host "   [IMPORTED] GUID: $newGuid" -ForegroundColor Green
            $ImportedCount++
        }
        else {
            Write-Host "   [WARNING] Import returned success, but no new GUID was detected." -ForegroundColor Yellow
            $FailedCount++
        }
    }

    # ------------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------------
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "   POWER PLAN INSTALLATION SUMMARY      " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Imported: $ImportedCount" -ForegroundColor Green
    Write-Host "Skipped:  $SkippedCount" -ForegroundColor Gray
    Write-Host "Failed:   $FailedCount" -ForegroundColor $(if ($FailedCount -gt 0) { "Red" } else { "Gray" })

    if ($FailedCount -gt 0) {
        Write-Host "Some plans could not be processed. Run the script again to retry." -ForegroundColor Yellow
    }
    else {
        Write-Host "All power plan files have been processed." -ForegroundColor Green
    }
}
catch {
    Write-Host ""
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
}
