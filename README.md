# Windows Lab Admin

This module is a collection of cmdlets to administer a ***computer lab*** based on Windows OS.

A ***lab administrator*** usually has to perform the same operations on each computer like creating a new local account, setting a new password, restarting all computers, etc.

***WinLabAdmin*** module enables the administrator to perform those operations only once from his computer for every computer inside the lab.

I use this module to administer the ***school computer labs*** where I work as an IT assistant. 


### Based on Powershell Remoting Tecnology

It's ***PS remoting*** that permits you to run commands on a remote machine as if you were standing there executing yourself. When you run a command, it’s running on the remote computer and the results of that command come back to your computer.

## Terminology

**Win Lab**  
a computer lab where the administrator operates. Computers are equipped with Windows OS (10 or 11) and are connected to the same LAN.

**Main computer**  
the computer that the administrator uses to run this module cmdlets.

**Lab computer**  
a computer available in the lab, remote-controlled from the Main computer. Lab computers have similar hardware and software characteristics.

**Lab User Account**  
a local user account created on each lab computer with the same: `username`, `password`, and account type (Standard User or Administrator).  
These accounts never expire, the password never expires and can't be changed by the lab user.
  
## Getting the Lab ready
At this time, you need to move from computer to computer in the lab to operate.

Create the *Administrator* ***Lab User Account*** on each computer. Good usernames are ***LabAdmin*** or ***PSAdmin***, let's use ***PSAdmin***. You also need to create this account on the ***Main computer***.

Log in to each ***PSAdmin*** account created and follow these steps

1. Install Powershell ver 7.1+
2. Set network to *private* in Windows settings
3. Open the PS terminal as administrator and launch `Enable-PSRemoting` command 
4. *Main computer only*
    - Open the PS terminal and launch `Set-Item -Path WSMan:\localhost\client\TrustedHosts -Value *`  
    ***Disclaimer***: you are responsible for handling security issues. For instance, the *Main computer* should only be accessible to you, and the *PSAdmin* password should be known exclusively by you.

## Installation
Install [WinLabAdmin](https://www.powershellgallery.com/packages/WinLabAdmin/0.0.1) from PowerShell Gallery.

You need to install the module only on the ***Main computer***.
 
1. Log in to ***PSAdmin*** account
2. `PS> Install-Module -Name WinLabAdmin`
3. Close and reopen the terminal and aunch `get-command -Module WinLabAdmin`
4. Follow instructions to set `config.json`

Close and reopen the terminal again. Then, launch `get-command -Module WinLabAdmin`. If the module has been installed correctly, you should see the list of cmdlets.

## List of cmdlets

`Copy-ToLabUserDesktop`  
`Disconnect-AnyUser`  
`New-LabUser`  
`Remove-LabUser`  
`Restart-LabComputer`  
`Set-LabUser`  
`Show-Config`  
`Start-LabComputer`  
`Stop-LabComputer`  
`Sync-LabComputerDate`  
`Test-LabComputerPrompt`  
`Restore-LabComputerDesktop`  
`Save-LabComputerDesktop`
