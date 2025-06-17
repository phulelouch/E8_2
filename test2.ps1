# Privileged Access Event Logging Audit Commands

# ML2-RA-06: Privileged access events are centrally logged

# Check for Event ID 4672 - Special privileges assigned to new logon
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672} -MaxEvents 100 | Select-Object TimeCreated, @{Name='Account';Expression={$_.Properties[1].Value}}, @{Name='Privileges';Expression={$_.Properties[4].Value}} | Format-Table -AutoSize

# Check for Event ID 4625 - Failed logon attempts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 100 | Select-Object TimeCreated, @{Name='Account';Expression={$_.Properties[5].Value}}, @{Name='LogonType';Expression={$_.Properties[10].Value}}, @{Name='FailureReason';Expression={$_.Properties[8].Value}} | Format-Table -AutoSize

# ML2-RA-07: Privileged account and group management events are centrally logged

# Check for Event ID 4738 - User account modified
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4738} -MaxEvents 100 | Select-Object TimeCreated, @{Name='ModifiedAccount';Expression={$_.Properties[1].Value}}, @{Name='ModifiedBy';Expression={$_.Properties[4].Value}} | Format-Table -AutoSize

# Check for Event ID 4728 - Member added to security group
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4728} -MaxEvents 100 | Select-Object TimeCreated, @{Name='MemberAdded';Expression={$_.Properties[0].Value}}, @{Name='GroupName';Expression={$_.Properties[2].Value}}, @{Name='AddedBy';Expression={$_.Properties[6].Value}} | Format-Table -AutoSize

# Check for Event ID 4729 - Member removed from security group
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4729} -MaxEvents 100 | Select-Object TimeCreated, @{Name='MemberRemoved';Expression={$_.Properties[0].Value}}, @{Name='GroupName';Expression={$_.Properties[2].Value}}, @{Name='RemovedBy';Expression={$_.Properties[6].Value}} | Format-Table -AutoSize

# Check for Event ID 4737 - Security group changed
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4737} -MaxEvents 100 | Select-Object TimeCreated, @{Name='GroupModified';Expression={$_.Properties[1].Value}}, @{Name='ModifiedBy';Expression={$_.Properties[4].Value}} | Format-Table -AutoSize

# Verify audit policy settings for these events
auditpol /get /category:"Logon/Logoff"
auditpol /get /category:"Account Management"

# Check if events are being forwarded to central logging server (if using Windows Event Forwarding)
wecutil es

# Alternative: Export events for specific time range (last 24 hours)
$StartTime = (Get-Date).AddDays(-1)
$EndTime = Get-Date

# Export all privileged access events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672,4625; StartTime=$StartTime; EndTime=$EndTime} | Export-Csv -Path "ML2-RA-06_PrivilegedAccessEvents.csv" -NoTypeInformation

# Export all account/group management events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4738,4728,4729,4737; StartTime=$StartTime; EndTime=$EndTime} | Export-Csv -Path "ML2-RA-07_AccountGroupManagementEvents.csv" -NoTypeInformation
