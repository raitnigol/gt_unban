# Run the script as administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

# Registry keys to delete.
$29549 = "HKCU:\Software\Microsoft\29549"
$29548 = "HKCU:\Software\Microsoft\29548"
$Cryptography = "HKLM:\Software\Microsoft\Cryptography" 
$HostName = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$RANDOMKEYarray = @()

# Get registry keys from HKCU:\
Get-ChildItem -Path HKCU:\[0-9]* | ForEach-Object {
    $random_key = Get-ChildItem -Path HKCU:\[0-9]* | Select-Object -ExpandProperty PSPath
    $RANDOMKEYarray = @()
    $RANDOMKEYarray += $random_key #.Split("::") -Like "HKEY*"
}
# Get save.dat
$LocalAppData = [Environment]::GetFolderPath('LocalApplicationData')
$SaveData = "$LocalAppData\Growtopia\save.dat"

# Generate a hostname
$hostname_length = 16 # change this value according to your needings
$NewHostName = -Join ((48..57) + (97..122) | Get-Random -Count $hostname_length | % {[char]$_})

# Delete keys and save.dat
if (Test-Path $29548) {
    Remove-Item $29548 -Recurse
    Write-Host "Successfully removed registry key $29548"
}
else {
    Write-Host "Destination $29548 does not exist"
    $errors += 1
}

if (Test-Path $29549) {
    Remove-Item $29549 -Recurse
    Write-Host "Successfully removed registry key $29549"
}
else {
    Write-Host "Destination $29549 does not exist"
    $errors += 1
}

if (Test-Path $Cryptography) {
    Remove-ItemProperty -Path $Cryptography -Name "MachineGuid"
    Write-Host "Successfully removed registry key MachineGuid from $Cryptography"
}
else {
    Write-Host "Registry key MachineGuid not found from $Cryptography"
    $errors += 1
}

if (Test-Path $HostName) {
    Set-ItemProperty -Path $Hostname -Name "HostName" -Value "$NewHostName"
    Write-Host "Successfully set the hostname to $NewHostName"
}
else {
    Write-Host "Registry key HostName not found from $Hostname"
    $errors += 1
}

if (Test-Path $SaveData) {
    Remove-Item $SaveData
}
else {
    Write-Host "Save.dat not found from destination $SaveData"
    $errors += 1
}

if ($RANDOMKEYarray.Length -gt 0) {
    if (Test-Path $RANDOMKEYarray) {
    Remove-Item -Path $RANDOMKEYarray -Recurse
    Write-Host "Successfully removed the key keys from HKCU:\ (total keys: $($RANDOMKEYarray.Length))"
    }
}
else {
    Write-Host "Failed to delete keys from HKCU:\, no keys found."
    $errors += 1
}

if ($errors -ne 0) {
    Write-Host "Total errors: $errors"
}
else {
    Write-Host "Success. All registry keys were deleted."
}
# Prompt for exiting the window
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")