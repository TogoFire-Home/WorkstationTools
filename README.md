# ⚡ Workstation Tools

This repository provides powerful scripts designed to **automate and standardize the setup of new Windows workstations**. Our goal is to streamline the post-installation process, ensuring a productive, consistent, and high-performance environment with minimal manual effort.

-----

## 🎯 Purpose

The main script in this repository aims to:
* **Accelerate Initial Setup**: Automatically install necessary package managers and fundamental tools.
* **Standardize the Environment**: Ensure all workstations have a consistent set of core software and registry tweaks.
* **Performance Tuning**: Apply advanced system optimizations that go beyond standard Windows settings.
* **Save Time**: Drastically reduce the time spent on manual app installation and OS debloating.

-----

## 📂 Repository Contents

  * **`CoreTools.ps1`**: This is the main PowerShell script that automates the installation of various essential tools and applications, and configures necessary environment variables.

-----

## 🤖 How to Use

### Prerequisites
* **[Windows PowerShell](https://github.com/PowerShell/PowerShell/releases/latest) 5.1+**
* **Administrator Privileges** (Mandatory)

### 🚀 Quick Execution (One-Liner)
Run the following command to execute the script directly in memory:

```powershell
iex (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/TogoFire-Home/WorkstationTools/main/CoreTools.ps1")
```

-----

### 💾 Local Execution (Offline Mode)
Use this if you want to save the script to your `%TEMP%` folder before running:

```powershell
$path = "$env:TEMP\CoreTools.ps1"; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/TogoFire-Home/WorkstationTools/main/CoreTools.ps1" -OutFile $path; (Get-Content $path) -replace 'Set-ExecutionPolicy', '#Set-ExecutionPolicy' | Set-Content $path; powershell.exe -ExecutionPolicy Bypass -File $path
```

-----

## 🛠️ CoreTools.ps1 Features Overview

### 📟 System & Performance
* **RAM Optimization:** Sets `SvcHostSplitThreshold` dynamically based on your RAM (Winaero logic).
* **MSConfig Boot Fix:** Procedural **BCD & Registry fix** that ensures **"Number of Processors"** is unchecked.
   <details>
   <summary><b>Why is this important? (Click to expand)</b></summary>

   > Many users manually check this option thinking it boosts performance or decreases boot time. In reality, it creates a **hard limit** at boot, stripping Windows of its ability to dynamically manage threads, leading to thermal issues and crashes in apps like **Google Chrome**.
   </details>

* **Update Control:** Hard-pauses Windows Updates until the year 3000 and blocks driver auto-updates.
* **Update Behavior:** **Prevents automatic restarts** after updates while a user is signed in.
* **Network & Power:** Removes QoS bandwidth limits and disables network in Modern Standby.
* **DNS Optimization:** Enhances **DNS Cache TTL** and table size for **faster domain resolution**.
* **Debloat:** Kills background apps, telemetry (Office/PS), and gaming overlays (Game Bar).
* **Startup Management:** Force-disables common social, gaming, and utility apps from Task Manager using binary status codes (**03**) in the Registry.
* **User Security:** Force-sets **"Password Never Expires"** for the **Admin** account to prevent unexpected lockouts.
* **Login & Security:** Disables **CTRL+ALT+DEL** requirement by force-syncing the **Registry (`DisableCAD=1`)** with the **Local Security Policy (SecPol.msc)** database, ensuring the UI correctly shows "Enabled" (Do not require).
* **Crash Analysis:** Enables **Detailed BSOD (DisplayParameters)** to show technical information during system crashes.

### 🌐 Universal Browser Debloat
* **Multi-Browser Sync:** Applies privacy and performance policies to **Chrome, Brave, Edge, and Firefox**.
* **Anti-Bloat:** Disables **Copilot (Edge), Leo AI (Brave), Pocket (Firefox)**, and built-in VPNs/Wallets.
* **Privacy & Speed:** Blocks telemetry, background modes, hardware acceleration, and auto-updates.
* **Pass Management:** Ensures "Offer to save passwords" remains enabled across all engines.
* **Print Spooler ACL:** Grants **Full Control** permissions to the **"Everyone"** group using a Universal SID (`S-1-1-0`) to resolve persistent access-related print errors.


### ☁️ OneDrive Deep Clean
* **Safe Migration:** Automatically moves user data from OneDrive back to local folders before removal.
* **Full Purge:** Uninstalls the client and wipes registry/leftover folders (includes a 5s safety prompt).

### 💻 Dev Stack & Git Workspace
* **Package Managers:** Auto-installs **Chocolatey**, **Winget**, and **PowerShell 7**.
* **GitHub Setup:** Configures global Git settings (`protectNTFS`) and enables **Case Sensitivity** (fsutil) on the GitHub folder.
* **Software:** Deploys 7zip, Git, VS Codium, VLC, Python 3+, HF-CLI, and more via Choco/Winget.
* **Runtimes:** Installs **AutoHotkey v2+** and **Dart SDK** with automatic System PATH integration.

### 📦 Interactive App Deployment (Winget)
* **Media Extensions & Codecs:** Automated deployment and version-aware updates for **HEVC (Free-Codecs)** and **8 critical Codec extensions** (AV1, VP9, JXL, RAW, etc.) via Winget Store IDs.
* **Communication & Security:** Interactive setup for **FluentFlyout, TubeDigger, Signal, Sticky Password, WhatsApp, and Outlook** via Store IDs.
* **AI Ecosystem:** Optional deployment of **ChatGPT and Perplexity** desktop apps.
* **Smart Interface:** Uses **WScript.Shell Popups** with 5-second timeouts and a final installation summary.
* **Gaming Essentials:** **One-click pack** (Steam, Discord, EA, Epic, Xbox) with automated Store ID matching and 5s skip.

### ⚙️ Shell & UI Tweaks
* **Explorer UI Opt (Win 11+):** Automatic detection of Windows 11 to enable **Snap Layouts** and force-disable automatic frequent folders. Includes an **interactive 5s prompt** to reset Quick Access cache only when needed, preserving your manual pins by default.
* **Universal Take Ownership:** Adds a high-compatibility context menu with an **orange checkmark icon**, using a native `.reg` import to bypass registry locks.
* **Legacy Cleanup:** Silently scans and **removes old/broken context menu entries** (CMD/PS) before applying new ones.
* **grepWin Shell Purge:** Uses native `reg.exe` for high-speed **removal of all grepWin context menu entries**, bypassing PowerShell's registry provider overhead for a cleaner system shell.
* **Start Menu Refactor:** Automated renaming of specific system tool folders for better aesthetics, including a recursive cleanup of redundant shortcuts and orphaned `.lnk` files.
* **Volume Identity:** Force-sets the System Drive (C:) label to a standardized name and purges localized desktop clutter for a cleaner initial experience.
* **Multi-Language Support:** All custom menus now **detect the system language** (22+ languages supported) for labels and legal notices.
* **Advanced Desktop Tools:** Adds a categorized menu for **Control Panel**, **Safe Mode** (4 options), **Task Killer**, and **Explorer Restart**.
* **Spooler Repair Tool:** Adds a localized context menu entry that triggers a silent, elevated repair script in `C:\Windows`. **Note:** Automatically detects **Windows Server** environments to disable the service instead of adding the menu, ensuring server-side security.
* **Advanced Thumbnailing:** Integrated **Icaros Thumbnailer** deployment via GitHub API, ensuring high-quality previews for specialized video and image formats.
* **Context Menus:** Adds "Open CMD/PS here" (Shift+Right-click) with **UNC/Network path support** and moves Git Bash/GUI to Shift+Right-click only.
* **Context Limit:** Increases right-click limit to **128 items** (allows many files selected at once).
* **Explorer Navigation:** Sets startup location to **This PC** and forces **User Folders (Downloads, etc.)** under This PC.
* **Visuals:** Restores "New Text Document", pins Recycle Bin to sidebar, and fixes wallpaper quality (100%).
* **Performance Visuals:** Enforces **"Show thumbnails instead of icons"** and enables **"Drop shadows for icon labels"** on the desktop via Registry to optimize the UI appearance.
* **Defaults:** Enables NumLock on login, disables mouse acceleration, and sets **Alt+Tab to show up to 20 browser tabs**.

### 🧩 Optional Scripts (5s Skip Prompt)
* **System Digital Entitlement:** Automated check and configuration of system features.
* **StartAllBack:** Option to run the **StartAllBack Update Blocker** automatically.

-----

## 🤝 Contribution

Contributions are welcome\! If you have suggestions for improving this script, adding new tools, or fixing issues, feel free to open an issue or submit a pull request.

-----

## 📜 License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

-----

## ✨ Related Projects
* [StartAllBack Update Blocker](https://github.com/TogoFire-Home/WorkstationTools/blob/main/StartAllBack-Update-Blocker/README.md)

-----
