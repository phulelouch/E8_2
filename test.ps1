# AD Privileged Account Audit PowerShell Commands

# 1. Find privileged accounts with no account expiry set
Get-ADUser -Filter {(admincount -eq 1) -and (enabled -eq $true)} -Properties AccountExpirationDate | Where-Object {$_.AccountExpirationDate -like ""} | Select @{n='Username'; e={$_.SamAccountName}}, @{n='Account Expiration Date'; e={$_.AccountExpirationDate}}, @{n='Enabled'; e={$_.Enabled}}

# 2. Find privileged accounts with expiry date greater than 12 months
Get-ADUser -Filter {(admincount -eq 1) -and (enabled -eq $true)} -Properties AccountExpirationDate | Where-Object {$_.AccountExpirationDate -gt (Get-Date).AddMonths(12)} | Select @{n='Username'; e={$_.SamAccountName}}, @{n='Account Expiration Date'; e={$_.AccountExpirationDate}}, @{n='Enabled'; e={$_.Enabled}}

# 3. Find privileged accounts inactive for more than 45 days
Get-ADUser -Filter {(admincount -eq 1) -and (enabled -eq $true)} -Properties LastLogonDate | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-45) -and $_.LastLogonDate -ne $null} | Select @{n='Username'; e={$_.samaccountname}}, @{n='Last Logon Date'; e={$_.LastLogonDate}}, @{n='Enabled'; e={$_.enabled}}

# 4. Get number of devices with LAPS
Get-ADComputer -Filter {ms-Mcs-AdmPwdExpirationTime -like "*"} -Properties ms-Mcs-AdmPwdExpirationTime | measure

# 5. Get number of enabled devices in Active Directory
Get-ADComputer -Filter {Enabled -eq $true} | measure

# 6. Find service accounts with passwords older than 12 months
# Replace SVC_* with your service account naming convention
$PassLastSetTimeFrame = (Get-Date).AddMonths(-12)
Get-ADUser -Filter "enabled -eq 'true' -and SamAccountName -like 'SVC_*'" -Properties pwdlastset | Where-Object{$_.pwdlastset -like '0' -or ([datetime]::FromFileTime($_.pwdLastSet) -lt $PassLastSetTimeFrame)} | Select-Object SAMAccountName, @{name ="pwdLastSet"; expression={([datetime]::FromFileTime($_.pwdLastSet))}}
