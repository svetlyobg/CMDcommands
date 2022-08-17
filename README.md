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

## How to Check NTP Server Date & Time Using Windows Command Line
w32tm /stripchart /computer:localhost /dataonly /samples:3

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

## Kill stuck Outlook
taskkill /IM outlook.exe

## Add Office 365 User to the Administrators Group

```powershell
net localgroup administrators AzureAD\SvetLyo /add
```

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

## Add an app to run automatically at startup in Windows 10

Windows logo key + R,type ```shell:startup```, then select OK. This opens the Startup folder. Copy and paste the shortcut to the app from the file location to the Startup folder.

## Disable Outlook Desktop Search

```cmd
rem reg add "HKLM\Software\Policies\Microsoft\Windows" /v PreventIndexingOutlook /t REG_DWORD /d 1 /f
```

## Replace "Ease of Access" Button with Other Programs on Login Screen

```cmd
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /t REG_SZ /d cmd.exe /f
```

## Delete Files With Specific Content

```powershell
#Get-ChildItem "." -Filter *.eml -Recurse | Select-String "undeliverable"| Select Filename, LineNumber, Line, Path | Format-Table > filename.txt
Get-ChildItem "." -Filter *.eml -Recurse | Select-String "undeliverable"| Select Filename | Format-Table > filename.txt
Get-Content .\filename.txt
#Manually remove obsolete lines
Get-Content .\filename.txt | Remove-Item -Verbose
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
At the end, navigate to C:\Users\$env:UserName\AppData\Roaming\Microsoft\Network\Connections\Pbk and edit the rasphone.pbk file by changing PreviewUserPw=0 from 1 to 0

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

## Check Windows Defender Exclusions
```bat
reg query "HKLM\Software\Microsoft\Windows Defender\Exclusions\Extensions"
reg query "HKLM\Software\Microsoft\Windows Defender\Exclusions\IpAddresses"
reg query "HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths"
reg query "HKLM\Software\Microsoft\Windows Defender\Exclusions\Processes"
reg query "HKLM\Software\Microsoft\Windows Defender\Exclusions\TemporaryPaths"
```

## Robocopy
robocopy "A:\source\" "B:\destination\" /E /ZB /COPYALL /R:2 /W:2 /MT:6 /LOG+:c:\robocopy.log /tee

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

## Create .zip Archive via PowerShell

```powershell
Compress-Archive -LiteralPath ".\outlook.pst" -DestinationPath ".\outlook.zip" -CompressionLevel Optimal -Force -Verbose
```
or
```powershell
$source = '.'
$destination = "C:\Users\$env:UserName\Desktop"
$subfolders = Get-ChildItem $source -Directory -Recurse
Compress-Archive -Path $source -DestinationPath "$destination\archive.zip" -CompressionLevel Fastest -Force -Verbose
```

You can also add the date and time

```powershell
$d = Get-Date -Format "dddd-MM-dd-yyyy"
Compress-Archive -LiteralPath ".\0\" -DestinationPath ".\$d.zip" -CompressionLevel Optimal -Force -Verbose
```

## Create .zip Archive via 7z cmd

```cmd
"C:\Program Files\7-Zip\7z" a -tzip "C:\archive_%date%_.zip" "M:\Ethical Hacking\tools\*.*" -r -mm=LZMA -mmt=on -mx9 -md=256m -mfb=256 -sccUTF-8 "-p0" -mem=AES256
```

## Update current .zip Archive via 7z cmd

```cmd
"C:\Program Files\7-Zip\7z" u "C:\tmp\archive.zip" "M:\Ethical Hacking\3 SCANNING & ENUMERATION\*.*"
```

## Dump SQL to website folder, create password protected zip via 7z and delete the SQL file

```cmd
"C:\Program Files\MySQL\MySQL Server 5.7\bin\mysqldump.exe" -u USER -pPASSWORD -h SERVERNAME DATABASENAME > "WEBSITELOCATION\DATABASE.sql"
"C:\Program Files\7-Zip\7z" a -tzip "BACKUPLOCATION\%date%_.zip" WEBSITELOCATION\*.*" -r -mm=LZMA -mmt=on -mx9 -md=256m -mfb=256 -sccUTF-8 "-pPUTAPASSWORDHERE" -mem=AES256
del "WEBSITELOCATION\DATABASE.sql"
```

```powershell
Push-Location "C:\Program Files\MySQL\MySQL Server 5.7\bin\"
.\mysqldump.exe -u USER -pPASSWORD -h SERVERNAME DATABASENAME > "WEBSITELOCATION\DATABASE.sql"
$d = Get-Date -Format "dd-MM-yyyy-dddd"
Compress-Archive -LiteralPath "WEBSITELOCATION\" -DestinationPath "BACKUPLOCATION\$d.zip" -CompressionLevel Optimal -Force
Push-Location "WEBSITELOCATION"
Remove-Item DATABASE.sql
```

## Recursively Delete Folder and Its Subfolders

```powershell
## 1
Get-ChildItem -Path "C:\archive" -File -Recurse | Remove-Item -Verbose

## 2
$folderPath = "C:\archive\"
$user = "$env:USERNAME"
$accesstype = "FullControl"
$argList = $user, $accesstype, $allowOrDeny
$allowOrDeny = "Allow"
$acl = Get-Acl $folderPath
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $argList
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($user, $accesstype, $allowOrDeny)
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl $folderPath

## 3
$folderPath = "C:\archive\"
$user = "$env:USERNAME"
$grant = "/grant:r"
$permission = ":(OI)(CI)(F)"
$inhertance = "/inheritance:e"
Invoke-Expression -Command ('icacls $folderPath $inhertance $grant "${user}${permission}"')
```


# Active Directory

## Offline Domain Join

Needs CMD as Administrator on Both Machines. On the DC type:

```cmd
djoin.exe /provision /domain "EXAMPLE.LOCAL" /machine "CLIENTPCNAME" /savefile C:\join.txt
```
Copy Over the File to the Client's Machine. In CMD type:

```cmd
djoin.exe /requestodj /loadfile C:\join.txt /windowspath %systemroot% /localos
```

## Export Windows Custom Event Logs for the past 30 days

```powershell
Get-EventLog -LogName System -After ((get-date).AddDays(-30)) -EntryType Error, Warning  |  ConvertTo-Csv | Out-File -FilePath C:\Users\$env:UserName\Desktop\EVENTLOGS\SYSTEMlast30days.csv -Force

Get-EventLog -LogName Security -After ((get-date).AddDays(-30)) -EntryType Error,FailureAudit,SuccessAudit,Warning |  ConvertTo-Csv | Out-File -FilePath C:\Users\$env:UserName\Desktop\EVENTLOGS\SECURITYlast30days.csv -Force

Get-EventLog -LogName Application -After ((get-date).AddDays(-30)) -EntryType Error, Warning |  ConvertTo-Csv | Out-File -FilePath C:\Users\$env:UserName\Desktop\EVENTLOGS\APPLICATIONlast30days.csv -Force

Get-EventLog -LogName Security -After ((get-date).AddDays(-1)) | where {$_.EventID -eq 4771} |  ConvertTo-Csv | Out-File -FilePath .\Secyritylast1dayID4771.csv -Force
```

## Export SysMon Event log as .xml

```cmd
WEVTUtil query-events "Microsoft-Windows-Sysmon/Operational" /format:xml /e:sysmonview > c:/sysmon/sysmoneventlog.xml
```

## Check for all disabled AD users

```powershell
Search-ADAccount –AccountDisabled –UsersOnly –ResultPageSize 2000 –ResultSetSize $null | Select-Object SamAccountName, DistinguishedName
```

## Check for all enabled AD users

```powershell
 Get-ADUser -Filter 'enabled -eq $true' | Select-Object GivenName, Name,  SamAccountName, UserPrincipalName | ConvertTo-Html | Out-File .\enabled.html
```

## Get information about all Server Roles and Features

```powershell
Get-WindowsFeature | Where-Object {$_. installstate -eq "installed"} | Format-List Name,Installstate
```

# Exchange

## Check user email usage
Get-MailboxStatistics "*EmailAddress*" | Select-Object -Property DisplayName,TotalitemSize

## Check all user email usage

Get-Mailbox -ResultSize Unlimited | Get-MailboxStatistics | Sort-Object TotalItemSize -Descending | Select-Object DisplayName,TotalItemSize

## Check Sent/Received emails

> Get-MessageTrackingLog -ResultSize Unlimited -Sender *EmailAddress* -Recipients *EmailAddress* | out-gridview

## Check Exchange ActiveSync and OWA for Devices are enabled for a user

> Get-MobileDeviceStatistics -Mailbox svet@example.com | Select -Property LastSuccessSync, LastSyncAttemptTime, DeviceUserAgent, DeviceModel, DeviceFriendlyName, DeviceOS ,Guid | Convertto-Csv | Out-File svet-devices.csv

## Get User's Group Membership and Shared Mailbox Statistics

```powershell
Get-ADPrincipalGroupMembership Svet | Select Name

Get-ADUser Svet -Properties Memberof | Select -ExpandProperty memberOf

Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize:Unlimited | Select-Object Identity,Alias,DisplayName | Sort DisplayName

```
## Exchange (Shared) Mailbox Permissions

### List all mailboxes to which a particular user has Full Access permissions

```powershell
Get-Mailbox | Get-MailboxPermission -User Svet
```

### List all shared/user/room/whatever mailboxes to which particular user has Full Access permissions

```powershell
Get-Mailbox -RecipientTypeDetails UserMailbox,SharedMailbox -ResultSize Unlimited | Get-MailboxPermission -User Svet
```

### List all mailboxes to which members of a particular security group have access

```powershell
Get-Mailbox | Get-MailboxPermission -User Svet
```

### List all mailboxes to which a user has Send As permissions

```powershell
Get-Mailbox | Get-RecipientPermission -Trustee Svet
```

(If you see the error <<The term 'Get-MailboxPermission' is not recognized as the name of a cmdlet>> please add the snapin):

```powershell
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;
```

### List all user mailboxes to which members of a particular security group have Send As access

```powershell
Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited | Get-RecipientPermission -Trustee Svet
```

### List all mailboxes to which a particular security principal has Send on behalf of permissions

```powershell
Get-Mailbox | ? {$_.GrantSendOnBehalfTo -match "Svet"}
```

### List all (shared) mailboxes without any Full Access permissions other than self

```powershell
Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited | ? { (Get-MailboxPermission $_.UserPrincipalName | ? {$_.User -ne "NT AUTHORITY\SELF"}).Count -eq 0 }
```

### List all mailboxes without any Send on behalf of permissions

```powershell
Get-Mailbox -ResultSize Unlimited -Filter {GrantSendOnBehalfTo -eq $null}
```

## Y2K22 Workaround - Disable-AntimalwareScanning

```powershell
cd "C:\Program Files\Microsoft\Exchange Server\V15\Scripts"
.\Disable-AntimalwareScanning.ps1
Restart-Service MSExchangeTransport -Verbose
```

## Get Exchange services status

```powershell
Get-Service *exchange* | Where-Object {$_.Status -eq "Running"}
```

# IIS Web Server

## Remove Server Response Header

Create an outbound rule

```
RESPONSE_Server
```

![RESPONSE_Server](/img/RESPONSE_Server.png)


## www to non www redirect in .htaccess
<IfModule mod_rewrite.c>
        RewriteEngine On
        RewriteBase /
        RewriteCond %{HTTP_HOST} ^www\.(.*)$ [NC]
        RewriteRule ^(.*)$ https://%1/$1 [R=301,L]
    </IfModule>

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

## Export IIS websites and bindings

> %windir%\system32\inetsrv\appcmd list site > c:\sites.xls

> Get-WebBinding | ConvertTo-Csv | Out-File "C:\bindings.csv" -Force -Verbose

> Get-Website | ConvertTo-Csv | Out-File "C:\sites.csv" -Force -Verbose

```powershell
Get-Website | Select-Object -ExpandProperty Bindings | ft
$ws = Get-Website
$ws.PhysicalPath
$ws.PhysicalPath | ConvertTo-Html | Out-File C:\Users\$env:UserName\Desktop\path.html
$ws.Bindings.Collection
$ws.Bindings.Collection | ConvertTo-Html | Out-File C:\Users\$env:UserName\Desktop\bindings.html
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


## Bulk check website php version
1. Upload the phpinfo.php file in the website root dir
2. In a text file add all website URL to be scanned
3. Use Linux ```bash wget -i sites.txt``` to get all the data
4. Find in files the php version using Notepad++
5. Open all results as tabs in Notepadd++
6. Find in files $_SERVER['SERVER_NAME'] to list the websites using the php version from point 4

## Create SelfSigned Certificate to Digitally Sign PowerShell Scripts

```powershell
New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert -Subject "CN=Svet Kosev" -FriendlyName "Svet Kosev PowerShell" -NotAfter 12-07-2023
$cert = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert -Subject "CN=Svet Kosev" -FriendlyName "Svet Kosev PowerShell" -NotAfter 12-07-2023
Move-Item -Path $cert.PSPath -Destination "Cert:\CurrentUser\Root"
$CodeCert = Get-ChildItem -Path "Cert:\CurrentUser\Root" -CodeSigningCert
Set-AuthenticodeSignature -FilePath ..\exportLog.ps1 -Certificate $CodeCert
```

## Hyper-V

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

## Convert OVA to VHD via PowerShell (VirtualBox is required)

```powershell
cd C:\Program Files\Oracle\VirtualBox
.\VBoxManage.exe clonemedium --format vhd "F:\VMs\wazuh-4.3.5-disk-1.vmdk" "F:\VMs\wazuh-4.3.5-disk-1.vhd"
```
![Convert From OVA to VHD](/img/OVAtoVHD.png)

## Office 365/Azure

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

## How do you find these X largest files?

```powershell
Get-ChildItem .\ -recurse | Sort-Object length -descending | select-object -first 32 | ft name,length -wrap –auto
```

## Add Office 365 User to the Administrators Group

```powershell
net localgroup administrators AzureAD\SvetLyo /add
```


# Other

## recycle bin path in Windows 10
C:\$Recycle.Bin

## Enable GPedit in Windows 10 Home

run this in cmd.exe as an admin:

> pushd "%~dp0" 

> dir /b %SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~3*.mum >List.txt 

> dir /b %SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~3*.mum >>List.txt 

> for /f %%i in ('findstr /i . List.txt 2^>nul') do dism /online /norestart /add-package:"%SystemRoot%\servicing\Packages\%%i" 

> pause

## Export Windows Firewall Rules

```powershell
get-netfirewallrule | select-object name, group, action, enabled, profile | export-csv C:\firewallrulesexported.csv
```
