![GitHub all releases](https://img.shields.io/github/downloads/svetlyobg/CMDcommands/total?logo=GitHub&style=flat-square)
![GitHub repo size](https://img.shields.io/github/repo-size/svetlyobg/CMDcommands)
![GitHub top language](https://img.shields.io/github/languages/top/svetlyobg/CMDcommands)
![GitHub language count](https://img.shields.io/github/languages/count/svetlyobg/CMDcommands)
![GitHub pull requests](https://img.shields.io/github/issues-pr/svetlyobg/CMDcommands)
![GitHub issues](https://img.shields.io/github/issues/svetlyobg/CMDcommands)
![Twitter Follow](https://img.shields.io/twitter/follow/svkosev?style=social)

# usefulCMDcommands

## ipconfig
Quickly Find Your local IP Address

## ipconfig /all
Detailed IP Address

## ipconfig /flushdns
Flush Your DNS Resolver Cache

## ipconfig /renew
Renew IP Address

## ipconfig /release
Release IP Address

## ipconfig /flushdns
Flush Your DNS Resolver Cache

## ipconfig /registerdns
Updates a host A/AAAA record within your active directory integrated DNS

## ipconfig /displaydns
Displays the contents of the DNS Resolver Cache

## netsh winsock reset
Resetting Network Adapter (Winsock Reset)

## getmac
Get mac addresses

## ping *hostname or IP address*
Send packets to that address

## ping -a *IP address*
Send packets to that address and returns the hostname

## ping *hostname* -4
Send packets to that hostname and returns the IPv4 address

## ping *hostname* -6
Send packets to that hostname and returns the IPv6 address

## tracert *hostname or IP address*
Traces the route it takes for a packet to reach a destination

## pathping
Trace route and provide network latency and packet loss for each router and link in the path. Combines the functionality of PING and TRACERT.

## arp -a
Checks availabe hosts on the network

## shutdown
shutdown /s /t 0 - immediate shutdown<br>
shutdown /r /t 0 - immediate restart<br>
shutdown /r /o - restarts the computer into advanced options<br>
Shutdown Shortcuts

## chkdsk
CHKDSK is a Windows utility that can check the integrity of your hard disk and can fix various file system errors.

## chkdsk c: /f /r /v
/f - fix errors
/r - relocate bad sectors
/v - displays the path of every file


## sfc /scannow
Scan System Files for Problems

## DISM /Online /Cleanup-Image /CheckHealth
Determine if there are any corruptions inside the local image. However, the option won't perform any repairs.

## DISM /Online /Cleanup-Image /ScanHealth
Alternatively, you can run DISM with the ScanHealth option to perform a more advanced scan to check if the Windows 10 image has any problems

## DISM.exe /Online /Cleanup-image /Restorehealth
Fix Windows Update errors - RestoreHealth option, which will run an advanced scan and repair any problems automatically.

## DISM /Online /Cleanup-Image /RestoreHealth /Source:repairSource\install.wim
Fix image issues  using a DVD/USB with Windows 10

## telnet
Connect to Telnet Servers

## cipher /w:
Permanently Delete and Overwrite a Directory
cipher /w:C:\Users\svetlozar\Desktop\testDel

## rmdir *Folder Path* /s
Removes directory even if it is not empty

## netstat -an
List Network Connections and Ports

## nbtstat -a *IP or host*
Rsetrieve the mac addressses for a remote computer

## nslookup *example.org*
Find the IP Address Associated With a Domain

## whoami
Displays the current domain and user name

## hostname
Displays the computer's hostname

## netplwiz
Shows users on the computer (Network places wizard)

## net user Svet 1234 /ADD
Creates user Svet and sets the password to 1234

## net localgroup Administrators Svet /add
Adds user to group

## WMIC USERACCOUNT WHERE Name='Svet' SET PasswordExpires=FALSE
Sets the password for Svet to never expire

## Create admin user and password and set it to never expire
net user Svet 1234 /ADD && net localgroup Administrators Svet /add && WMIC USERACCOUNT WHERE Name='Svet' SET PasswordExpires=FALSE

## Find Hard Disk Serial Number
wmic diskdrive get Name, Manufacturer, Model, InterfaceType, MediaType, SerialNumber.

## winver
Find the Windows version

## devmgmt.msc
Device manager

## taskmgr
Task manager

## gpupdate /force
Force Update Group Policy

## assoc
Display or change the association between a file extension and a fileType
assoc .doc=word

## driverquery
Lists all installed device drivers and their properties
driverquery -v
Optain more information

## systeminfo
List system configuration

## perfmon /report
Generate System Performance Report

## powercfg
Control power settings, configure Hibernate/Standby modes.

## powercfg /hibernate on
Turns on hibernation

## powercfg /hibernate off
Turns off hibernation

## powercfg -a
Lists all available PC power saving states

## powercfg /energy
Generates power consumption report

## tasklist
TaskList displays all running applications and services with their Process ID

## tasklist -svc
Shows services related to each task use

## tasklist -v
Detailed task list

## tasklist -m
Locates .dll files

## taskkill -pid 0000
Kills the task with process ID of 0000

## MRT.exe
Microsoft Windows Malicious Software Removal Tool

mrt /? - help

mrt /f - force full scan

## Windows list psysical  disks
wmic diskdrive list brief

## Get Windows Key
wmic path softwarelicensingservice get OA3xOriginalProductKey

## Portqry
troubleshoot TCP/IP connectivity issues
[Download PortQryV2.exe, a command-line utility that you can use to help troubleshoot TCP/IP connectivity issues. Portqry.exe runs on Windows 2000-based computers](https://www.microsoft.com/en-us/download/details.aspx?id=17148)

## tpm.msc
Check for the Trusted Platform Module

## control panel
Opens Control Panel

## compmgmt
Computer Management

## taskmgr
Task manager

## rasphone
Create/connect to a (VPN) network

## mdsched.exe
Run Windows Memory Diagnostic Tool

## Using Driver Verifier to identify issues with Windows drivers
verifier.exe /standard /all

## Restore Task Manager Back From Sysinternals Proccess Explorer

> reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v Debugger

## www to non www redirect in .htaccess
<IfModule mod_rewrite.c>
        RewriteEngine On
        RewriteBase /
        RewriteCond %{HTTP_HOST} ^www\.(.*)$ [NC]
        RewriteRule ^(.*)$ https://%1/$1 [R=301,L]
    </IfModule>

## Add an app to run automatically at startup in Windows 10

Windows logo key + R,type ```shell:startup```, then select OK. This opens the Startup folder. Copy and paste the shortcut to the app from the file location to the Startup folder.

# PowerShell

## Get-ChildItem -Path '.\' -Recurse | Unblock-File
Unblocks blocked file in the current directory and it's childrens

## slmgr
Software Licensing Management Tool
slmgr /dli - checks part of the product key

## Get Windows 10 Key
powershell “(Get-WmiObject -query ‘select * from SoftwareLicensingService’).OA3xOriginalProductKey”

## Start/Stop Microsoft Veeam Service powershell

Get-service -displayname veeam* | stop-service
Get-service -displayname veeam* | start-service

## .\HOSTNAME.exe
Displays the computer's hostname

## Check TCP-IP Listening port
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "PortNumber"

## Set TCP-IP Listening port
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "PortNumber" -Value 3423
New-NetFirewallRule -DisplayName 'RDPPORTLatest' -Profile 'Public' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3423

## Check for open port

```powershell
Test-NetConnection -ComputerName **HOSTNAME** -Port **PORTNUMBER**
```

## List Installed Software Programs via Powershell

```powershell
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize
```

```powershell
Get-WmiObject win32_product
```

```powershell
Get-CimInstance win32_product
```

## How to restart IIS Website and Application Pool

```powershell
#Restart a Web App Pool and IIS a Wesbsite
#CopyLeft SVET :)

$wap = Read-Host -Prompt 'Input the Web App Pool Name'
Write-Host "`n$line"
Write-Host "Next actions will be performed on App Pools and IIS websites that contain $wap in their name !!!" -ForegroundColor Yellow
Write-Host "`n$line"

Get-Website -Name *$wap*
Get-WebAppPoolState -Name *$wap*

$yesno = Read-Host -Prompt 'Do you wish to proceed with stopping the website? y/n:'

if ($yesno -like 'y'){

Restart-WebAppPool -Name *$wap* -verbose
#Stop-WebAppPool -Name *$wap* -verbose
#Start-WebAppPool -Name *$wap* -verbose
Write-Host "`n$line"
Write-Host "App Pools that contain $wap were sucessfully restarted!" -ForegroundColor Green
Write-Host "`n$line"


Stop-Website *$wap* -Verbose
Write-Host "`n$line"
Write-Host "IIS Websites that contain $wap in their name were STOPPED !!!" -ForegroundColor RED
Write-Host "`n$line"

Start-Website *$wap* -Verbose
Write-Host "`n$line"
Write-Host "IIS Websites that contain $wap in their name were sucessfully started!" -ForegroundColor Green
Write-Host "`n$line"

Write-Host "The Window will close in 5 seconds"
Start-Sleep -Seconds 5
}

else {
    Write-Host Negative User Choise
}
```


## Restart Server's Application Pools

```cmd
& $env:windir\system32\inetsrv\appcmd list apppools /state:Started /xml | & $env:windir\system32\inetsrv\appcmd recycle apppools /in
```

## Restart IIS Server

```cmd
iisreset /start
```

## Stop IIS Website and Application Pool

```powershell
#Stop a Web App Pool and IIS a Wesbsite
#CopyLeft SVET :)

$wap = Read-Host -Prompt 'Input the Web App Pool Name'
Write-Host "`n$line"
Write-Host "Next actions will be performed on App Pools and IIS websites that contain $wap in their name !!!" -ForegroundColor Yellow
Write-Host "`n$line"

Get-Website -Name *$wap*
Get-WebAppPoolState -Name *$wap*

$yesno = Read-Host -Prompt 'Do you wish to proceed with stopping the website? y/n:'

if ($yesno -like 'y'){

Stop-WebAppPool -Name *$wap* -verbose
#Start-WebAppPool -Name *$wap* -verbose
Write-Host "`n$line"
Write-Host "App Pools that contain $wap were sucessfully stopped!" -ForegroundColor Green
Write-Host "`n$line"


Stop-Website *$wap* -Verbose
Write-Host "`n$line"
Write-Host "IIS Websites that contain $wap in their name were STOPPED !!!" -ForegroundColor RED
Write-Host "`n$line"

Write-Host "The Window will close in 5 seconds"
Start-Sleep -Seconds 5

}

else

{
    Write-Host Negative User Input!
}

```

## Remove IIS Website and Application Pool

```powershell
#Stop a Web App Pool and IIS a Wesbsite
#CopyLeft SVET :)

$wap = Read-Host -Prompt 'Input the Web App Pool Name'
Write-Host "`n$line"
Write-Host "Next actions will be performed on App Pools and IIS websites that contain $wap in their name !!!" -ForegroundColor Yellow
Write-Host "`n$line"

Get-Website -Name $wap
Get-WebAppPoolState -Name $wap

$yesno = Read-Host -Prompt 'Do you wish to proceed with stopping the website? y/n:'

if ($yesno -like 'y'){

Remove-WebAppPool -Name $wap -verbose
#Start-WebAppPool -Name *$wap* -verbose
Write-Host "`n$line"
Write-Host "App Pool was sucessfully removed!" -ForegroundColor Green
Write-Host "`n$line"

Get-Website -Name $wap
Remove-Website $wap -Verbose
Write-Host "`n$line"
Write-Host "IIS Website was sucessfully removed !!!" -ForegroundColor RED
Write-Host "`n$line"

Write-Host "The Window will close in 5 seconds"
Start-Sleep -Seconds 5

}

else {
    Write-Host Negative User Choise
}
```

## Export IIS Websites and Their Bindings

```powershell
$site = Read-Host -Prompt 'Input the website  Name'
Write-Host "`n$line"
Write-Host "Next actions will be performed on IIS websites that contain $site in their name !!!" -ForegroundColor Yellow
Write-Host "`n$line"

Wrrite-Host "Total bindings are "
Get-WebBinding -Name $site | measure
Get-WebBinding -Name $site

Write-Host "SSL Bindings are"
Get-WebBinding -name $site | Where-Object -Property sslFlags -eq 1
Get-WebBinding -name $site | Where-Object -Property sslFlags -eq 1 | measure

Write-host "NO SSL bindings are"
Get-WebBinding -name $site | Where-Object -Property sslFlags -eq 0
Get-WebBinding -name $site | Where-Object -Property sslFlags -eq 0 | measure


Start-Sleep -Seconds 5
```

## Export Windows Custom Event Logs for the past 30 days

```powershell
Get-EventLog -LogName System -After ((get-date).AddDays(-30)) -EntryType Error , Warning  |  ConvertTo-Csv | Out-File -FilePath C:\Users\%username%\Desktop\EVENTLOGS\SYSTEMlast30days.csv -Force

Get-EventLog -LogName Security -After ((get-date).AddDays(-30)) -EntryType Error,FailureAudit,SuccessAudit,Warning |  ConvertTo-Csv | Out-File -FilePath C:\Users\%username%\Desktop\EVENTLOGS\SECURITYlast30days.csv -Force
```

## Import JSON to PowerShell

1. Import the JSON file to a variable

```powershell
$import = Get-Content .\json.json
$import
```

![Import the JSON file to a variable](https://github.com/svetlyobg/CMDcommands/blob/master/Import%20JSON%20to%20PowerShell/1-get-json-content.png)

2. Convert from JSON to PowerShell object

```powershell
$import = Get-Content .\json.json | ConvertFrom-Json
$import
```

![Convert from JSON to PowerShell object](https://github.com/svetlyobg/CMDcommands/blob/master/Import%20JSON%20to%20PowerShell/2-convert-from-json-to-powershell-object.png)

3. Get object Members, Properties and Methods

```powershell
$import | Get-Member
```

![Get object Members, Properties and Methods](https://github.com/svetlyobg/CMDcommands/blob/master/Import%20JSON%20to%20PowerShell/3-get-members-properties-and-methods.png)

4. Get actual information

```powershell
$import.members
$import.members.age
```

![Get object Members, Properties and Methods](https://github.com/svetlyobg/CMDcommands/blob/master/Import%20JSON%20to%20PowerShell/4-get-actual-information.png)

## Create .zip Archive via PowerShell

```powershell
Compress-Archive -LiteralPath ".\outlook.pst" -DestinationPath ".\outlook.zip" -CompressionLevel Optimal -Force -Verbose
```


# Batch

## check.NET version
@echo off
cmd /k reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\full" /v version

## Automatically enable VPN for RDP and closes it on exit
# Set up the VPN using rasphone.exe and save the user credentials
(put the .bat file in the same location as .rdp file)

```bat
@echo off

:: Connecting to VPN...
rasphone.exe -d  "ChangeMeVPN-NAME"

echo Running RDP...
"ChangeMeRDP-NAME.rdp"

echo Finished - disconnecting from VPN...
rasphone.exe -h "ChangeMeVPN-NAME"
```
At the end, navigate to C:\Users\%username%\AppData\Roaming\Microsoft\Network\Connections\Pbk and edit the rasphone.pbk file by changing PreviewUserPw=0 from 1 to 0

## Disable Windows 10 PIN

```bat
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions" /v value /t REG_DWORD /d 0 /f
```

## Disable Windows telemetry

```bat
rem Windows Telemetry must not be configured to Full
reg add "HKLM\Software\Policies\Microsoft\WindowsDataCollection\" /v AllowTelemetry /t REG_DWORD /d 0 /f

rem If Enhanced diagnostic data is enabled it must be limited to the minimum required to support Windows Analytics
reg add "HKLM\Software\Policies\Microsoft\WindowsDataCollection\" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f
```

# Other

## recycle bin path in Windows 10
C:\$Recycle.Bin

# Exchange Console

## Check user email usage
Get-MailboxStatistics "*EmailAddress*" | Select-Object -Property DisplayName,TotalitemSize

## Check all user email usage

Get-Mailbox -ResultSize Unlimited | Get-MailboxStatistics | Sort-Object TotalItemSize -Descending | Select-Object DisplayName,TotalItemSize

## Check Sent/Received emails

> Get-MessageTrackingLog -ResultSize Unlimited -Sender *EmailAddress* -Recipients *EmailAddress* | out-gridview

## Export IIS websites and bindings

> %windir%\system32\inetsrv\appcmd list site > c:\sites.xls

> Get-WebBinding | ConvertTo-Csv | Out-File "C:\bindings.csv" -Force -Verbose

> Get-Website | ConvertTo-Csv | Out-File "C:\sites.csv" -Force -Verbose

## Enable GPedit in Windows 10 Home

run this in cmd.exe as an admin:

> pushd "%~dp0" 

> dir /b %SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~3*.mum >List.txt 

> dir /b %SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~3*.mum >>List.txt 

> for /f %%i in ('findstr /i . List.txt 2^>nul') do dism /online /norestart /add-package:"%SystemRoot%\servicing\Packages\%%i" 

> pause

## Enable Hyper-V in Windows Home

```bat
pushd "%~dp0"
dir /b %SystemRoot%\servicing\Packages\*Hyper-V*.mum >hyper-v.txt
for /f %%i in ('findstr /i . hyper-v.txt 2^>nul') do dism /online /norestart /add-package:"%SystemRoot%\servicing\Packages\%%i"
del hyper-v.txt
Dism /online /enable-feature /featurename:Microsoft-Hyper-V -All /LimitAccess /ALL
pause
```

## Perform Hyper-V Planned Replication Failover and Failback via PowerShell

```powershell
Get-VM

$vmname = Read-Host -Prompt "Choose a VM for Failover"

$status = Get-VM -ComputerName Server2012 -Name $vmname | Select -ExpandProperty Status
$state = Get-VM -ComputerName Server2012 -Name $vmname | Select -ExpandProperty State

Write-Host Status is $status and State is $state

if ( $status -like "Operating Normally" -and $status -like "Running")

{
    Write-Host Stopping $vmname now... -ForegroundColor Yellow
    Stop-VM -ComputerName Server2012 -Name $vmname
    Write-Host $vmname has been shutted down -ForegroundColor Green
    Start-Sleep -Seconds 5
}

else

{
    Write-Host Please turn it off manually!!!
    Start-Sleep -Seconds 5
}

#Fail Over Steps
Get-VMReplication 

Write-Host Preparing planned failover of the primary VM -ForegroundColor Yellow
Start-VMFailover -Prepare -VMName $vmname -ComputerName Server2012
Write-Host Preparing Completed -ForegroundColor Green

Write-Host Failing over the Replica virtual machine -ForegroundColor Yellow
Start-VMFailover -VMName $vmname -ComputerName DC
Write-Host Failing over Completed -ForegroundColor Green

Get-VMReplication

Write-Host Switching the Replica virtual machine to a primary virtual machine -ForegroundColor Yellow
Set-VMReplication -Reverse -VMName $vmname -ComputerName DC
Write-Host Switching Completed -ForegroundColor Green

Write-Host Starting the virtual machine -ForegroundColor Yellow
Start-VM -VMName $vmname -ComputerName DC
Write-Host $vmname is up and running -ForegroundColor Green

Get-VMReplication 

Start-Sleep -Seconds 5

#Fail Back Steps
Get-VMReplication 

Write-Host Preparing planned failover of the replica VM -ForegroundColor Yellow
Start-VMFailover -Prepare -VMName $vmname -ComputerName DC
Write-Host Preparing Completed -ForegroundColor Green

Write-Host Failing over the Primary virtual machine -ForegroundColor Yellow
Start-VMFailover -VMName $vmname -ComputerName Server2012
Write-Host Failing over Completed -ForegroundColor Green

Get-VMReplication 

Write-Host Switching the primary virtual machine to a replica virtual machine -ForegroundColor Yellow
Set-VMReplication -Reverse -VMName $vmname -ComputerName Server2012
Write-Host Switching Completed -ForegroundColor Green

Write-Host Starting the virtual machine -ForegroundColor Yellow
Start-VM -VMName $vmname -ComputerName Server2012
Write-Host $vmname is up and running -ForegroundColor Green

Get-VMReplication 

Start-Sleep -Seconds 5
```

## How to Set an Individual Password to Never Expire in Office 365

Open PowerShell with elevated privileges.

```powershell
Install-Module AzureAD
Install-Module MSOnline
$credential = Get-Credential
Connect-MsolService -Credential $credential
Set-MsolUser -UserPrincipalName <name of the account> -PasswordNeverExpires $true
Set-MsolUser -UserPrincipalName user@example.com -PasswordNeverExpires $true
```

## Check for all disabled AD users

```powershell
Search-ADAccount –AccountDisabled –UsersOnly –ResultPageSize 2000 –ResultSetSize $null | Select-Object SamAccountName, DistinguishedName
```

## Export Windows Firewall Rules

```powershell
get-netfirewallrule | select-object name, group, action, enabled, profile | export-csv C:\firewallrulesexported.csv
```
