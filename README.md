# PC Lab Utility
###### (1st draft)

This utility is a module of Powershell cmdlets I use to administer ***school PC labs*** where I work as an IT assistant. 

A typical *school PC lab* has 15 PCs with Windows OS, and I have to perform the same operation on each one like creating a new local account, setting a new password, restarting all computers, etc.

This module enables me to perform those operations only once from my computer for every PC in the lab.


### PS Remoting based

***PC Lab Utility*** is based on *Powershell Remoting Technology*. PS remoting enables you to execute tasks on a remote machine as if you were standing there executing yourself. When you run a command, it’s running on the remote computer and the results of that command come back to your computer.

## Terminology

#### PC Lab
a space where the *master and remote PCs* are located, all connected to the same LAN, all equipped with Windows OS (10 or 11).

#### Master PC 
the PC the administrator uses to control remote PCs, this PC can execute cmdlets on remote PCs.

#### Remote PC
the PCs available in the lab with similar hardware and software characteristics. They are remote-controlled from the master PC.

#### Common User
a Windows local user account created on each remote PC with the same: `username`, `password`, and account type (Standard User or Administrator).

These accounts never expire, the password never expires and can't be changed by the user.
  

## Getting the Lab ready
Before using the Utility ensure you have an administrator local account on every remote and master PC with the same username and password. For example, name these special accounts ***RemoteAdmin*** but you can choose the name you prefer.

Log in to the ***RemoteAdmin*** account on every *remote and master PC* and follow these steps

1. Install Powershell ver 7.1 or later 
2. In windows settings, set network to *private* 
3. Open the PS terminal as administrator and launch `Enable-PSRemoting` command 
4. **For the master PCC only**
    - Open the PS terminal and launch `Set-Item -Path WSMan:\localhost\client\TrustedHosts -Value *`  
    ***Disclaimer***: It's up to you to handle security issues. For example, the master PC should not be accessible to anyone other than you, and the RemoteAdmin password should be known only by you.

## Installation
1. name a folder exactly `PCLabUtil` on your master PC and download in it the files: `config.json.example`, `PCLabUtil.psm1`, `install-module.ps1`;
2. rename `config.json.example` in `config.json`;
3. edit `config.json` filling in remote PC names in you lab. Don't care about Mac Addresses at this step;
4. open the PS (v7.1+) terminal in `PCLabUtil` folder and execute the script `.\install-module.ps1`;

You can also clone the repo and go through steps 2 to 4.

Close and reopen terminal, then launch `get-command -Module PCLabUtil`, If the module has been correctly installed, you should see the list of cmdlets.

## Available cmdlets

`Copy-ToCommonUserDesktop`  
`Disconnect-AnyUser`  
`New-CommonUser`  
`Remove-CommonUser`  
`Restart-EveryComputer`  
`Set-CommonUser`  
`Show-Config`  
`Start-EveryComputer`  
`Stop-EveryComputer`  
`Sync-EveryComputerDate`  
