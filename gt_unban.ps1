<#
This script is made for Ubisoft's sandbox game Growtopia.
The purpose of this script is to make unbanning yourself from Growtopia easier, with a single click.
How the script works:
    It takes the registry keys from HKCU:\ and HKLM:\ and deletes them.
    It also changes the hostname to a 16 random letter one (can be modified to be longer or shorter)
    It deletes the save.dat file from Growtopia's install location
This script requires atleast PowerShell V3.0
This script also requires admin permissions to delete the MachineGuid registry key.
#>

# Run the script as administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

# Registry keys to delete.
$HostName = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$Cryptography = "HKLM:\Software\Microsoft\Cryptography" 
$HKCUkeyarray = @() # Array to store HKCU:\ keys if contains multiple
$HKLMkeyarray = @() # Array to store HKLM:\ keys if contains multiple

# Get registry keys from HKCU:\
Get-ChildItem -Path HKCU:\[0-9]* | ForEach-Object {
    $HKCU_key = Get-ChildItem -Path HKCU:\[0-9]* | Select-Object -ExpandProperty PSPath
    $HKCUkeyarray = @()
    $HKCUkeyarray += $HKCU_key #.Split("::") -Like "HKEY*"
}

# Get registry keys from HKLM:\
Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\[0-9]* | ForEach-Object {
    $HKLM_key = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\[0-9]* | Select-Object -ExpandProperty PSPath
    $HKLMkeyarray = @()
    $HKLMkeyarray += $HKLM_key #.Split("::") -Like "HKEY*"
}

# Get save.dat
$LocalAppData = [Environment]::GetFolderPath('LocalApplicationData')
$SaveData = "$LocalAppData\Growtopia\save.dat"

# Generate a new hostname and replace it with the new one.
$hostname_length = 16 # change this value according to your needings
$NewHostName = -Join ((48..57) + (97..122) | Get-Random -Count $hostname_length | % {[char]$_})
if (Test-Path $HostName) {
    Set-ItemProperty -Path $Hostname -Name "HostName" -Value "$NewHostName"
    Write-Host "Successfully set the hostname to $NewHostName"
} else {
    Write-Host "Registry key HostName not found from $Hostname"
    $errors += 1
}

# Delete MachineGuid and save.dat
if (Test-Path $Cryptography) {
    Remove-ItemProperty -Path $Cryptography -Name "MachineGuid"
    Write-Host "Successfully removed registry key MachineGuid from $Cryptography"
} else {
    Write-Host "Registry key MachineGuid not found from $Cryptography"
    $errors += 1
}

if (Test-Path $SaveData) {Remove-Item $SaveData} else {
    Write-Host "Save.dat not found from destination $SaveData"
    $errors += 1
}

# Delete registry keys from HKCU:\ and HKLM:\
if ($HKCUkeyarray.Length -gt 0) {
    if (Test-Path $HKCUkeyarray) {
    Remove-Item -Path $HKCUkeyarray -Recurse
    Write-Host "Successfully removed the key keys from HKCU:\ (total keys: $($RANDOMKEYarray.Length))"
    }
} else {
    Write-Host "Failed to delete keys from HKCU:\. No keys found."
    $errors += 1
}

if ($HKLMkeyarray.Length -gt 0) {
    if (Test-Path $HKLMkeyarray) {
    Remove-Item -Path $HKLMkeyarray -Recurse
    Write-Host "Successfully removed the key keys from HKLM:\ (total keys: $($HKLMkeyarray.Length))"
    }
} else {
    Write-Host "Failed to delete keys from HKLM:\. No keys found."
    $errors +=1
}

if ($errors -ne 0) {Write-Host "Total errors: $errors"}
else {Write-Host "Success. All registry keys were deleted."}

# Prompt for exiting the window
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")