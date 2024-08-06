# WindowsLab

Tools to administer a Windows OS computer lab. Tools are cmdlets packaged as a Powershell Module.

Usually a ***Lab Admin*** has to perform the same operations on each computer lab like 
* creating or removing a new local account, 
* restarting all computers,
* update date and time
* etc.

***WindowsLab*** enables the *Lab Admin* to perform those operations only once from his computer for every computer inside the lab.

I utilize this module to administer *Windows computer labs* at the school where I work as an IT assistant. 


### Based on Powershell Remoting Tecnology

It's ***PS remoting*** that permits you to run commands on a remote machine as if you were standing there executing yourself. When you run a command, it’s running on the remote computer and the results of that command come back to your computer.

## Terminology

**Lab**  
The computer lab where the administrator operates. Computers are equipped with Windows OS (10 or 11) and are connected to the same LAN.

**Admin computer**  
The computer that the administrator uses to run this module cmdlets. It's connected to the same LAN.

**Lab computer**  
A computer available in the lab, remote-controlled from the Admin computer. Lab computers have similar hardware and software characteristics.

**Lab admin**  
The administrator of the lab. He has a local account on the Admin computer and each lab computer.

**Lab User**  
User with a generic username instead of a personal username, for example, *Student*, *Teacher*, or *Guest*.  

 The lab user has a local account on each lab computer with the same: `username`, `password`, and account type (Standard User or Administrator). These accounts never expire, the password never expires and can't be changed by the lab user.
  
## Getting the Lab ready

Before using the Windowslab module, you must prepare the lab and set up each computer individually. 

On the *Admin computer*, create the *Lab admin* account with administrator privileges. The username I prefer is ***LabAdmin***. Set a strong password.

Log in to the *LabAdmin* account just created and follow these three steps:

1. Install Powershell ver 7.1+
2. Set network to *private* in Windows settings
3. Open the PS terminal as administrator and launch `Enable-PSRemoting` command 

Additionally, just on the *Admin computer*, launch the command:  
`Set-Item -Path WSMan:\localhost\client\TrustedHosts -Value *`  

>***Disclaimer***:  
you are responsible for handling security issues.  
For instance, the *Admin computer* should only be accessible to you, and the *LabAdmin* password should be robust and secret.

Now, with patience, do the same on each Lab computer, create a *LabAdmin* account with the same password and administrator privileges and follow the steps from 1 to 3.

## Module installation
Install [WindowsLab](https://www.powershellgallery.com/packages/WindowsLab/0.9.0) module on the *Admin computer* from PowerShell Gallery.

1. Log in to *LabAdmin* account
2. `PS> Install-Module -Name WindowsLab`
3. Close and reopen the terminal and launch `get-command -Module WindowsLab`
4. Follow instructions to set `config.json`

Close and reopen the terminal again. Then, launch `get-command -Module WindowsLab`. If the module has been installed correctly, you should see the list of cmdlets available in the module.

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
