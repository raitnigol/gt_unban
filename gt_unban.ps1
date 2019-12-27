# Run the script as administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

# Registry keys to delete.
$29549 = "HKCU:\Software\Microsoft\29549"
$29548 = "HKCU:\Software\Microsoft\29548"
$Cryptography = "HKLM:\Software\Microsoft\Cryptography" 
$HostName = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

# Generate a hostname
$hostname_length = 16 # change this value according to your needings
$NewHostName = -Join ((48..57) + (97..122) | Get-Random -Count $hostname_length | % {[char]$_})

# Delete keys
if (Test-Path $29548) {Remove-Item $29548 -Recurse; "Successfully removed registry key $29548"}
else { Write-Host "Destination $29548 does not exist" }

if (Test-Path $29549) {Remove-Item $29549 -Recurse; "Successfully removed registry key $29549"}
else {Write-Host "Destination $29549 does not exist"}

if (Test-Path $Cryptography) {Remove-ItemProperty -Path $Cryptography -Name "MachineGuid"; "Successfully removed MachineGuid from path $Cryptography"}
else {Write-Host "Registry key MachineGuid not found from $Cryptography"}

if (Test-Path $HostName) {Set-ItemProperty -Path $Hostname -Name "HostName" -Value "$NewHostName"; Write-Host "Successfully set the hostname to $NewHostName"}
else {Write-Host "Registry key HostName not found from $Hostname"}

# Delete save.dat
$LocalAppData = [Environment]::GetFolderPath('LocalApplicationData')
$SaveData = "$LocalAppData\Growtopia\save.dat"
Remove-Item $SaveData

# Prompt for exiting the window
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")