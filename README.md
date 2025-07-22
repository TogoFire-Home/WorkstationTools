# 🚀 Workstation Tools

This repository provides powerful scripts designed to **automate and standardize the setup of new Windows workstations**, including the **installation of essential applications and tools**. Our goal is to streamline the setup process, ensuring a productive and consistent work environment with minimal manual effort.

-----

## 🎯 Purpose

The main script in this repository aims to:

  * **Accelerate Initial Setup**: Automatically install necessary package managers and fundamental tools.
  * **Standardize the Environment**: Ensure all workstations have a consistent set of core software.
  * **Save Time**: Drastically reduce the time spent on manual app installation and configuration.

-----

## 📂 Repository Contents

  * **`CoreTools.ps1`**: This is the main PowerShell script that automates the installation of various essential tools and applications, and configures necessary environment variables.

-----

## 🤖 How to Use

### For Windows PowerShell 5.1 or greater 💻

Use the command below to download and execute the `CoreTools.ps1` script directly. This command will prompt for **administrator privileges**, which are **mandatory** for the script to function correctly.

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/TogoFire-Home/WorkstationTools/main/CoreTools.ps1" -UseBasicParsing | Invoke-Expression
```

-----

### What `CoreTools.ps1` Does:

This script automates the installation and configuration of key software and tools, including:

  * Sets PowerShell execution policy.
  * Installs/checks for **Chocolatey** and **Winget**.
  * Installs/updates **AutoHotkey v2+** and **PowerShell 7 (pwsh)**.
  * Installs various essential apps via Chocolatey (e.g., 7zip, Git, VS Codium, VLC).
  * Ensures **Python v3+** is installed.
  * Configures **Dart SDK PATH** environment variable.

-----

## 🤝 Contribution

Contributions are welcome\! If you have suggestions for improving this script, adding new tools, or fixing issues, feel free to open an issue or submit a pull request.

-----

## 📜 License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

-----
