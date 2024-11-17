# WindowsLab PowerShell Module

**WindowsLab** is a PowerShell module designed to simplify the administration of computer labs with Windows PCs (10 or 11) connected to the same LAN.

## Key Features

- Start, restart, or stop all PCs remotely
- Synchronize date and time across all PCs
- Create and manage generic user accounts
- Update passwords for generic accounts
- Disconnect users from all PCs
- Deploy files to all PCs

**Note**: A **generic account** is a local account that exists on all lab PCs with identical username and password, typically used for standard, non-administrative purposes.

## Terminology

**AdminPC**:  
The single administrator PC used for lab management.

**LabPC**:  
PCs used by lab users (e.g., students) with similar hardware and software configurations.

**LabAdmin**:  
An administrator local account present on both the AdminPC and all LabPCs, configured with identical username and password across all machines.

**LabUser**:  
Generic accounts for lab users present on each LabPC. Multiple accounts can exist with usernames like *Student*, *Teacher*, or *User*.

**Note**: In addition to **LabAdmin** and **LabUser** accounts, other account types can exist, such as personal user accounts or specialized administrator accounts for different tasks.

## Lab Setup Prerequisites

Before installing WindowsLab, follow these steps:

1. Create the **LabAdmin** account on both the *AdminPC* and all *LabPCs*:
   - Use identical username and password across all machines
   - Grant administrator privileges
   - Example username: LabAdmin

2. For easier management, rename LabPCs using a numbered system (e.g., PC01, PC02, PC03). While optional, this naming convention simplifies lab administration.

### Configuration Steps

1. On each PC, log in to the **LabAdmin** account and complete these tasks:
   - Install PowerShell 7 or higher
   - Set the network to "Private" in Windows settings
   - Open PowerShell as Administrator and run:  
     ```powershell
     Enable-PSRemoting
     ```

2. On the **AdminPC** only, perform the above steps plus:
   ```powershell
   Set-Item -Path WSMan:\localhost\client\TrustedHosts -Value *
   ```

**Note**: You can automate the configuration steps using the *GettingLabReady.ps1* script:

1. Download the script from this repository
2. Open Windows PowerShell as administrator
3. Navigate to the script's directory
4. Execute:
   ```powershell
   powershell -ExecutionPolicy Bypass -File GettingLabReady.ps1
   ```

**Security Warning**: Ensure the AdminPC is properly secured and use a strong, unique password for the LabAdmin account.

## Module Installation

WindowsLab requires the [NtpTime](https://www.powershellgallery.com/packages/Ntptime) module for internet time synchronization. Install both modules on the AdminPC only.

1. Log in as **LabAdmin** on the AdminPC
2. Install the required modules:
   ```powershell
   Install-Module -Name NtpTime
   Install-Module -Name WindowsLab
   ```
3. Restart your PowerShell session to ensure the modules are properly loaded and verify the installation:
   ```powershell
   Get-Command -Module WindowsLab
   ```
   A list of available cmdlets indicates successful installation.

## Available Cmdlets

- `Disconnect-User`  
Disconnects all active users from LabPCs.

- `Deploy-Item`  
Deploys files or folders to specified LabUser desktops across all LabPCs.

- `New-LabUser`  
Creates new generic accounts (LabUsers) on all LabPCs.

- `Remove-LabUser`  
Removes specified generic accounts from all LabPCs.

- `Set-LabUser`  
Updates LabUser passwords and privileges across all LabPCs.

- `Start-LabPc`  
Powers on all WoL-capable LabPCs simultaneously.

- `Stop-LabPc`  
Shuts down or restarts all LabPCs. Can schedule daily automatic shutdowns.

- `Sync-LabPcDate`  
Synchronizes date and time across all LabPCs using internet time servers.

- `Test-LabPcPrompt`  
Verifies remote command connectivity between AdminPC and LabPCs.

- `Set-LabPcName`  
Launches a GUI for managing multiple labs, where you can define LabPC names and discover their MAC addresses. The stored configuration enables other cmdlets to identify lab PCs and supports WoL functionality.

## Technical Overview

WindowsLab utilizes PowerShell remoting to execute commands on remote LabPCs. Commands run on the remote machines with results returned to the AdminPC, enabling centralized management.

## Wake-on-LAN (WoL) Support

WoL enables remote power-on functionality via wired Ethernet. It's preferred over Wake-on-Wireless LAN (WoWLAN) for:
- Higher reliability
- Better security
- Broader hardware compatibility

To use the Start-LabPC cmdlet's WoL features:
1. Verify WoL support in each LabPC's BIOS/UEFI settings
2. Enable WoL if supported

## Usage Note

I developed and actively use this module to manage computer labs at the school where I work as an IT assistant.
