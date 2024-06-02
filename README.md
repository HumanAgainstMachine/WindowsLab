# Windows Lab Admin

This module is a collection of cmdlets to administer a ***computer lab*** based on Windows OS.

A ***lab administrator*** usually has to perform the same operation on each computer like creating a new local account, setting a new password, restarting all computers, etc.

***Windows Lab Admin*** module enables the administrator to perform those operations only once from his computer for every computer inside the lab.

I use this module to administer the ***school computer labs*** where I work as an IT assistant. 


### Based on Powershell Remoting Tecnology

It's ***PS remoting*** that permits you to run commands on a remote machine as if you were standing there executing yourself. When you run a command, it’s running on the remote computer and the results of that command come back to your computer.

## Terminology

**Windows Lab**  
a computer lab where the administrator operates. Computers are equipped with Windows OS (10 or 11) and are connected to the same LAN.

**Admin computer**  
the computer that the administrator uses to run commands on lab computers.

**Lab computer**  
a computer available in the lab, remote-controlled from the Admin computer. Lab computers have similar hardware and software characteristics.

**Lab User Account**  
a local user account created on each lab computer with the same: `username`, `password`, and account type (Standard User or Administrator).  
These accounts never expire, the password never expires and can't be changed by the lab user.
  
## Getting the Lab ready
At this time, you need to move from computer to computer in the lab to operate.

Create the *Administrator* ***Lab User Account***, good usernames are ***Admin***, ***RemoteAdmin*** or ***PSAdmin***. You also need to create the same account on the ***Admin computer***.

Let's say you choose as username ***PSAdmin***.


Log in to the every ***PSAdmin*** account and follow these steps

1. Install Powershell ver 7.1+
2. Set network to *private* in Windows settings
3. Open the PS terminal as administrator and launch `Enable-PSRemoting` command 
4. *Admin computer only*
    - Open the PS terminal and launch `Set-Item -Path WSMan:\localhost\client\TrustedHosts -Value *`  
    ***Disclaimer***: you are responsible for handling security issues. For instance, the *Admin computer* should only be accessible to you, and the *PSAdmin* password should be known exclusively by you.

## Installation
1. Name a folder `WindowsLabAdmin` on the *Admin Computer* and download the files: `config.json.example`, `WindowsLabAdmin.psm1`, `install-module.ps1`
2. Rename `config.json.example` in `config.json`
3. Update `config.json` with lab computer names in your lab, disregarding Mac Addresses at this step.
4. Open the PS terminal in the `WindowsLabAdmin` folder and run the script `.\install-module.ps1`

You can also clone the repository and follow steps 2 to 4.

Close and reopen the terminal. Then, launch `get-command -Module WindowsLabAdmin`. If the module has been installed correctly, you should see the list of cmdlets.

## Available cmdlets

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
