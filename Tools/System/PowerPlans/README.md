# ⚡ Custom Power Plans

A collection of optimized Windows power schemes (`.pow`) designed to tune system performance, latency, and energy efficiency.

---

## 🚀 How to Install

### Option 1: Install from the Repository

Run the following command in PowerShell:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force | Out-Null; iex (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/TogoFire-Home/WorkstationTools/main/Tools/System/PowerPlans/Install-PowerPlans.ps1")
```

**Security note:** This command downloads and executes a remote PowerShell script. Review the script's contents before running it, especially on a production system.

### Option 2: Install Local Power Plans

The included script automatically detects and imports every `.pow` file present in this directory into Windows.

1. Right-click `Add-All-PowerPlans.bat` and select **Run as administrator**.
2. The script scans the directory and registers all available power schemes automatically.

---

## 🛠️ Simple Power Plan Manager

The automated installation script (`Install-PowerPlans.ps1`) also deploys the official **Simple Power Plan Manager** utility (by FPSHeaven) to manage, switch, and inspect your power plans effortlessly.

### 📥 Automated Installation Path
- **Executable Location:** `C:\Program Files\Tools\Apps\Simple Power Plan Manager\Simple_power_plan_manager.exe`
- **Version Tracking:** `$env:APPDATA\SimplePowerPlanManager\versionsp.txt`
- **Start Menu Shortcut:** Automatically created in Windows Start Menu for easy access.

### ⚙️ Features
- **Dynamic Updates:** Automatically checks GitHub releases for the latest version and updates in-place if a new release is detected.
- **Lightweight & Portable:** Deployed cleanly into your standard tool directories without cluttering the system.

---

## ⚙️ How to Activate

After importing a power plan:

1. Open **Control Panel → Power Options**, or run `powercfg.cpl`.
2. Select the desired power plan.

### Quick PowerShell Activation

List all registered power plans and their GUIDs:

```powershell
powercfg /list
```

Activate a specific power plan using its GUID:

```powershell
powercfg /setactive GUID
```

Replace `GUID` with the actual power scheme GUID.

---

## 🧹 Remove Extra Power Plans

The `Remove-ExtraPowerPlans.ps1` script removes all registered Windows power plans except the default **Balanced** power plan.

### 🚀 Run Directly from the Repository

Run the following command in an elevated PowerShell session:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force | Out-Null; iex (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/TogoFire-Home/WorkstationTools/main/Tools/System/PowerPlans/Remove-ExtraPowerPlans.ps1")
```

### ⚙️ Features

- **Balanced Preservation:** Keeps the standard Windows Balanced power plan.
- **Automatic Activation:** Activates Balanced before attempting to remove other plans.
- **Bulk Cleanup:** Attempts to remove all other registered power plans, including imported custom schemes.
- **Execution Feedback:** Reports successfully removed plans and any failures.
- **Non-Destructive to Files:** Does not delete `.pow` files, installation directories, or JSON state files.

**⚠️ Important:** This operation permanently removes the selected power schemes from the Windows power configuration. Back up any custom plans you may want to restore before running the script. Plans protected by Windows or otherwise unavailable for deletion may remain installed.

---

## 🛠️ Essential `powercfg` Commands

Run these commands in Command Prompt or PowerShell. Administrator privileges may be required for certain operations.

### List Power Plans

```powershell
powercfg /list
```

Displays all registered power schemes and identifies the active plan.

### Import a Power Plan

```powershell
powercfg /import "C:\Path\To\PowerPlan.pow"
```

Imports a `.pow` file into Windows. Use `powercfg /list` afterward to find its new GUID.

### Duplicate a Power Plan

```powershell
powercfg /duplicatescheme GUID
```

Creates a copy of an existing power scheme. Replace `GUID` with the source plan's GUID.

### Activate a Power Plan

```powershell
powercfg /setactive GUID
```

Activates the specified power scheme.

### Delete a Power Plan

```powershell
powercfg /delete GUID
```

Deletes the specified power scheme. Make sure you identify the correct GUID before deleting a plan. Switch to another plan first if necessary.

### Export / Back Up a Power Plan

```powershell
powercfg /export "C:\PowerPlan-Backup.pow" GUID
```

Exports the selected power scheme to a `.pow` file for backup or transfer to another computer.

### Query a Power Plan

```powershell
powercfg /query GUID
```

Displays the detailed configuration of a specific power scheme, including its power settings and AC/DC values.

To query the currently active power scheme:

```powershell
powercfg /query
```

### Display Power Configuration Help

```powershell
powercfg /?
```

Lists the available commands and their usage.

---

## 💡 Recommended Default: Balanced

**The Windows Balanced power plan is the recommended starting point for most systems.**

Balanced dynamically adjusts processor performance and power consumption according to workload, instead of forcing unnecessarily aggressive settings at all times.

- **Adaptive performance:** Allows Windows to scale processor performance according to demand.
- **Lower unnecessary power consumption:** Avoids forcing the processor to maintain an unnecessarily high minimum performance state.
- **Thermal efficiency:** Can reduce unnecessary heat and power consumption during idle and light workloads.
- **Windows and OEM power management remain in control:** Preserves the intended interaction between Windows power policies, chipset drivers, firmware, and manufacturer-specific power management.

### AMD and Intel Compatibility

For AMD Ryzen systems, install the appropriate AMD chipset drivers and retain the power-management configuration recommended for your specific platform. AMD has specifically recommended the AMD Ryzen Balanced plan for certain older Zen+ and Zen 2 configurations on Windows 11; this guidance should not be generalized to every modern Ryzen system.

Intel systems also rely on Windows processor power management, platform firmware, chipset components, and manufacturer-specific policies.

**Important:** The Balanced plan does not guarantee the highest benchmark score or the lowest latency in every workload. However, it is a sensible default for everyday use because it balances responsiveness, energy efficiency, and platform-managed performance.

Custom plans should be evaluated on the target hardware using repeatable tests rather than assuming that more aggressive settings always deliver better performance.

---

## 📊 Recommended Plans for Everyday Use

| Power Plan | Recommendation | Primary Focus |
|---|---|---|
| **Balanced (Windows)** | Recommended default | Everyday use, responsiveness, and efficiency |
| **amit's low latency** | Custom alternative to test | Consistency and lower CPU busy overhead, according to the available comparison |
| **VTRL Optimized** | Alternative to test | Balanced performance characteristics |
| **Kizzimo Extreme LL** | Specialized testing | Low DPC latency |
| **Arsenza INTEL / EndGame** | Gaming-focused testing | Average FPS |
| **LLG Parking + E-core Fix** | Gaming-focused testing | Low-percentile FPS stability |

*These recommendations reflect the available comparative data, not a guarantee of better results on every computer. Gaming benchmarks do not automatically predict everyday responsiveness.*

---

## ⚠️ Important Notes

- Always record the original power plan GUID before making changes.
- Export a backup of any customized plan before modifying it.
- Avoid running multiple optimization scripts that change the same power settings.
- Do not assume that a higher minimum processor state, disabled PCIe power management, or other aggressive settings will improve performance.
- Test custom plans under the same conditions and compare performance, latency, temperatures, power consumption, and stability.
- OEM utilities and firmware may apply additional power-management policies beyond the settings shown by `powercfg`.

---

## 📚 Official Documentation & Sources

### Official Windows & Hardware Resources
- [Microsoft Learn — Power Policy Settings](https://learn.microsoft.com/en-us/windows/win32/power/power-policy-settings)
- [Microsoft Learn — Configure Power Settings](https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/configure-power-settings)
- [Microsoft Learn — Processor Power Management Options](https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/configure-processor-power-management-options)
- [AMD — Windows Performance Variation on Compatible AMD Processors](https://www.amd.com/en/resources/support-articles/faqs/PA-400.html)

### Power Plan Sources & Community Credits
- [AlchemyTweaks — Power Plans Collection](https://github.com/AlchemyTweaks/power-plans)
- [FPSHeaven — Windows Performance Power Plan](https://fpsheaven.com/pt-BR/blogs/news/fpsheavens-windows-performance-power-plan)
- [FPSHeaven — Simple Power Plan Manager](https://github.com/fpsheaven/Simple-Power-Plan-Manager)
- [insopti — PowerPlan Repository](https://github.com/insovs/insopti-PowerPlan)
