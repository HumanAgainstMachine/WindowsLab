# WindowsLab PowerShell Module

**WindowsLab** is a PowerShell module designed to simplify the administration of a computer lab running Windows OS. It provides cmdlets for common tasks such as:

- Starting, restarting, and stopping all computers.
- Updating date and time on all computers.
- Creating and removing local accounts.
- Changing passwords.
- Disconnecting users.
- Sending files to all computers at once.

## Terminology

**Lab**: The computer room with one AdminPC and multiple LabPCs, all running Windows (10 or 11) and connected via the same LAN.

**AdminPC**: The main computer used for lab management.

**LabPC**: A computer in the lab, typically with similar hardware and software configurations.

**LabAdmin**: The administrator of the lab, who has a local account with the same username and password on both the AdminPC and each LabPC.

**LabUser**: A lab user with a local account on each LabPC, typically with usernames like *Student,* *Teacher,* or *Learner.*

## Getting the Lab Ready

Before using WindowsLab, manually create the **LabAdmin** account on each PC with the same username and password, and grant it administrator privileges (e.g., username: LabAdmin).

1. Log in to each LabAdmin account and eather run the script *GettingLabReady.ps1* or follow these steps:
   - Install PowerShell version 7.1 or higher.
   - Set the network to "Private" in Windows settings.
   - Open PowerShell as Administrator and run:  
     ```powershell
     Enable-PSRemoting
     ```
2. On the **AdminPC** only, run:
   ```powershell
   Set-Item -Path WSMan:\localhost\client\TrustedHosts -Value *
   ```

**Disclaimer**: Ensure that the AdminPC is secured, and use a strong, secret password for the LabAdmin account.

**Note**: You can download the *GettingLabReady.ps1* script from this website and run it on both the AdminPC and each LabPC to automate the three steps outlined in point 1.

## Module Installation

WindowsLab depends on module *NtpTime* to take time from internet, it's required so install it.

```powershell
Install-Module -Name NtpTime
```

Now, you can install [WindowsLab](https://www.powershellgallery.com/packages/WindowsLab) from the Powershellgallery.

1. Log in as **LabAdmin** on the AdminPC.
2. Run:
   ```powershell
   Install-Module -Name WindowsLab
   ```
3. Close and reopen the terminal, then run:
   ```powershell
   Get-Command -Module WindowsLab
   ```
   You should see a list of available cmdlets if the installation was successful.

## Cmdlets Overview

- `Deploy-Item` – Send files to all LabPCs.
- `Disconnect-User` – Disconnect active users on LabPCs.
- `New-LabUser` – Create a new local user on all LabPCs.
- `Remove-LabUser` – Remove a local user from all LabPCs.
- `Set-LabPcName` – Opens a GUI where you can input LabPC names. These names are saved for the module to reference, ensuring consistent identification of each LabPC.
- `Set-LabUser` – Change LabUser settings on all LabPCs.
- `Show-LabPcMac` – Searches for and displays the MAC addresses of all LabPCs, highlighting any issues such as mismatches or errors for troubleshooting.
- `Start-LabPc` – Start LabPCs through WoL.
- `Stop-LabPc` – Stop LabPCs.
- `Sync-LabPcDate` – Sync date and time on all LabPCs.
- `Test-LabPcPrompt` – Tests if each LabPC is ready to accept commands from the AdminPC, ensuring remote connectivity is properly established.

## How It Works

WindowsLab uses PowerShell remoting, allowing you to execute commands on remote LabPCs as if you were physically there. When a command is run, it executes on the remote computer, with results returned to your AdminPC.

## WoL

WoL (Wake-on-LAN) is a networking standard for remotely powering on computers via wired Ethernet. It's preferred over Wake on Wireless LAN due to its greater reliability, security, and wider hardware support. Wired connections offer better stability and performance, making WoL more dependable for remote power-on tasks.

The WindowsLab Module's Start-LabPC function leverages Wake-on-LAN (WoL) technology to reliably turn on LabPCs.

## Notes

I use this module to manage computer labs at the school where I work as an IT assistant.
