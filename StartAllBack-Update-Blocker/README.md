# 🛡️ StartAllBack & StartIsBack Blocker

A comprehensive PowerShell-based security tool designed to fully block, manage, and monitor **StartAllBack** and legacy **StartIsBack** update and communication services.

---

## 🔍 Key Features

### 📡 Smart Detection
* **Multi-Location Scanning**: Automatically locates executables in common installation paths.
* **Registry & Process Analysis**: Identifies active instances and registry-based installations.
* **AppX/Store Support**: Detects Microsoft Store versions using `Get-AppxPackage` and scans `WindowsApps` folders.

### 🧱 Multi-Layer Blocking
* **Advanced Firewall**: Creates robust Inbound and Outbound rules for all discovered `.exe` files.
* **DNS-Level Protection**: Modifies the `hosts` file (IPv4 `0.0.0.0` and IPv6 `::0`) to sinkhole update servers.
* **Microsoft Store Shield**: 
    * Excludes packages from automatic updates via Registry.
    * Configures Store auto-update policies to prevent background upgrades.

### ⚙️ Automation & UX
* **Task Management**: Automatically disables or re-enables StartAllBack scheduled update tasks.
* **Formatted Output**: Clean UI using box characters and color-coded status messages.
* **Resilience**: Comprehensive error handling, DNS cache flushing, and administrator permission validation.

---

## 🔧 Management Modes

| Action | Description |
| :--- | :--- |
| **Block** | (Default) Applies firewall rules, hosts file entries, and registry blocks. |
| **Unblock** | Performs a full cleanup, restoring access and re-enabling tasks. |
| **Status** | Provides a detailed report of current blocks, Store packages, and task states. |

---

## 🚀 Usage Examples

Run the script from an **Elevated PowerShell (Administrator)** terminal.

```powershell
# Standard Blocking (Default action)
.\Block-StartAllBack.ps1
```

# Block without modifying the hosts file
```powershell
.\Block-StartAllBack.ps1 -Action Block -IncludeHostsFile $false
```

# Remove all blocking rules and restore connectivity
```powershell
.\Block-StartAllBack.ps1 -Action Unblock
```

# Check current system status and installed packages
```powershell
.\Block-StartAllBack.ps1 -Action Status
```

## 🚀 Quick Execution (One-Liner)

If you want to run the script directly from GitHub without downloading it manually, run the following command in an **Elevated PowerShell (Administrator)**:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force | Out-Null; iex (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/TogoFire-Home/WorkstationTools/main/StartAllBack-Update-Blocker/Block-StartAllBack.ps1")
```
