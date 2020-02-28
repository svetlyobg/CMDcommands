# usefulCMDcommands

## ipconfig
Quickly Find Your IP Address

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

## tracert *hostname or IP address*
Traces the route it takes for a packet to reach a destination

## pathping
Trace route and provide network latency and packet loss for each router and link in the path. Combines the functionality of PING and TRACERT.

## shutdown
shutdown /s /t 0 - immediate shutdown<br>
shutdown /r /t 0 - immediate restart<br>
shutdown /r /o - restarts the computer into advanced options<br>
Shutdown Shortcuts

## chkdsk
CHKDSK is a Windows utility that can check the integrity of your hard disk and can fix various file system errors.

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

## netstat -an
List Network Connections and Ports

## nslookup *example.org*
Find the IP Address Associated With a Domain

## whoami
Displays the current domain and user name

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

## Get Windows Key
wmic path softwarelicensingservice get OA3xOriginalProductKey

## Portqry
troubleshoot TCP/IP connectivity issues
[Download PortQryV2.exe, a command-line utility that you can use to help troubleshoot TCP/IP connectivity issues. Portqry.exe runs on Windows 2000-based computers](https://www.microsoft.com/en-us/download/details.aspx?id=17148)

# PowerShell

## Get-ChildItem -Path '.\' -Recurse | Unblock-File
Unblocks blocked file in the current directory and it's childrens

## slmgr
Software Licensing Management Tool
slmgr /dli - checks part of the product key

# Batch

## check.NET version
@echo off
cmd /k reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\full" /v version

## recycle bin path in Windows 10

C:\$Recycle.Bin

## Get Windows 10 Key
powershell “(Get-WmiObject -query ‘select * from SoftwareLicensingService’).OA3xOriginalProductKey”

## Start/Stop Microsoft Veeam Service powershell

Get-service -displayname veeam* | stop-service
Get-service -displayname veeam* | start-service