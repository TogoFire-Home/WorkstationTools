
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# ============================================================
# POWER PLAN CLEANUP - KEEP BALANCED ONLY
# Windows PowerShell 5.1
# ============================================================

Write-Host "`n[MODULE] Removing all power plans except Balanced..." -ForegroundColor Cyan

$BalancedGuid = "381b4222-f694-41f0-9685-ff5bb260df2e"

# ------------------------------------------------------------
# DETECT EXISTING POWER PLANS
# ------------------------------------------------------------

Write-Host ">> Detecting installed power plans..." -ForegroundColor Yellow

$powercfgOutput = & powercfg.exe /list 2>&1

if ($LASTEXITCODE -ne 0) {
    throw "Unable to query installed power plans."
}

$plans = @(
    foreach ($line in $powercfgOutput) {
        if ("$line" -match '\b([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})\b') {
            [PSCustomObject]@{
                Guid = $matches[1].ToLowerInvariant()
                Line = "$line"
            }
        }
    }
)

if ($plans.Count -eq 0) {
    throw "No power plans could be detected."
}

# ------------------------------------------------------------
# VERIFY BALANCED EXISTS BEFORE CHANGING ANYTHING
# ------------------------------------------------------------

if ($plans.Guid -notcontains $BalancedGuid) {
    throw "Balanced power plan not found. No plans were removed."
}

Write-Host "[OK] Balanced power plan found." -ForegroundColor Green

# ------------------------------------------------------------
# ACTIVATE BALANCED
# ------------------------------------------------------------

Write-Host ">> Activating Balanced power plan..." -ForegroundColor Yellow

& powercfg.exe /setactive $BalancedGuid

if ($LASTEXITCODE -ne 0) {
    throw "Unable to activate Balanced. No plans were removed."
}

Write-Host "[OK] Balanced is active." -ForegroundColor Green

# ------------------------------------------------------------
# REMOVE ALL OTHER POWER PLANS
# ------------------------------------------------------------

$removedCount = 0
$failedCount  = 0

$otherPlans = @(
    $plans | Where-Object { $_.Guid -ne $BalancedGuid }
)

foreach ($plan in $otherPlans) {
    Write-Host ">> Removing: $($plan.Line.Trim())" -ForegroundColor Yellow

    $deleteOutput = & powercfg.exe /delete $plan.Guid 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "   [REMOVED] $($plan.Guid)" -ForegroundColor Green
        $removedCount++
    }
    else {
        Write-Host "   [FAILED] $($plan.Guid)" -ForegroundColor Red

        if ($deleteOutput) {
            Write-Host "   $($deleteOutput -join ' ')" -ForegroundColor DarkYellow
        }

        $failedCount++
    }
}

# ------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "   POWER PLAN CLEANUP SUMMARY           " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Removed: $removedCount" -ForegroundColor Green
Write-Host "Failed:  $failedCount" -ForegroundColor $(if ($failedCount -gt 0) { "Red" } else { "Gray" })

Write-Host "`n>> Remaining power plans:" -ForegroundColor Cyan
& powercfg.exe /list

Write-Host "`n[OK] Cleanup finished." -ForegroundColor Green
