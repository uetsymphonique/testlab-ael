# Lab Setup — Windows Server 2022 Domain Controller

## Environment Overview

| Role | Hostname | IP |
| - | - | - |
| Domain Controller | `DC01` | `10.12.10.10` |
| IIS Server | `IIS01` | `10.12.10.20` |
| Workstation | `WS01` | `10.12.10.30` |

Domain: `testlab.local`

---

## Step 1 — Pre-configuration

Set hostname and static IP before promoting to DC.

```powershell
# Run as Administrator

# Rename computer
Rename-Computer -NewName "DC01" -Force

# Set static IP — if the machine has multiple NICs, identify the correct one first:
#   Get-NetAdapter | Select-Object Name, Status, MacAddress
# Then set $iface to the internal lab interface name, e.g.:
#   $iface = "Ethernet 3"
$iface = (Get-NetAdapter | Where-Object Status -eq "Up").Name

New-NetIPAddress -InterfaceAlias $iface `
    -IPAddress "10.12.10.10" `
    -PrefixLength 24 `
    -DefaultGateway "10.12.10.1"

# Point DNS to self (required before dcpromo)
Set-DnsClientServerAddress -InterfaceAlias $iface `
    -ServerAddresses "127.0.0.1"

Restart-Computer -Force
```

---

## Step 2 — Install AD DS Role

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
```

---

## Step 3 — Promote to Domain Controller

Creates a new forest `testlab.local`. Replace `<SafeModePassword>` with a strong password
(used for DSRM recovery mode).

```powershell
Import-Module ADDSDeployment

Install-ADDSForest `
    -DomainName "testlab.local" `
    -DomainNetbiosName "TESTLAB" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "<SafeModePassword>" -AsPlainText -Force) `
    -InstallDns `
    -Force
```

Server will reboot automatically after promotion. After reboot, log back in as
`TESTLAB\Administrator` and run:

```powershell
# ADWS is disabled by default after promotion — enable and start it
Set-Service ADWS -StartupType Automatic
Start-Service ADWS

# Verify AD is responding
Get-ADDomain | Select-Object Name, DomainMode, PDCEmulator
```

---

## Step 4 — DNS Configuration

### A Records for lab hosts

```powershell
# The testlab.local DNS zone may not be created automatically — check first
Get-DnsServerZone | Select-Object ZoneName, ZoneType

# If testlab.local is missing, create it
Add-DnsServerPrimaryZone -Name "testlab.local" -ReplicationScope "Forest" -PassThru

# IIS server — both virtual hostnames point to the same IIS01 IP
Add-DnsServerResourceRecordA -ZoneName "testlab.local" -Name "upload" -IPv4Address "10.12.10.20"
Add-DnsServerResourceRecordA -ZoneName "testlab.local" -Name "react"  -IPv4Address "10.12.10.20"

# Workstation
Add-DnsServerResourceRecordA -ZoneName "testlab.local" -Name "ws01" -IPv4Address "10.12.10.30"
```

### Conditional Forwarder for dnscat2 C2

The dnscat2 server listens for DNS queries under `attacker.local`. The DC must forward
that zone to the attacker machine so DNS tunnelling traffic reaches the C2 listener.

```powershell
Add-DnsServerConditionalForwarderZone `
    -Name "attacker.local" `
    -MasterServers "192.168.56.2" `
    -PassThru
```

Verify the forwarder is configured:

```powershell
Get-DnsServerZone | Where-Object ZoneType -eq "Forwarder"
```

Expected output: `attacker.local` with `ZoneType: Forwarder`. A timeout on
`Resolve-DnsName attacker.local` is normal at this stage — the forwarder is working
but the attacker's dnscat2 listener is not yet running.

---

## Step 5 — Create Domain Accounts

### (Optional) Privileged service account for lateral movement scenarios

```powershell
$adminPass = ConvertTo-SecureString "AdminPass123!" -AsPlainText -Force

New-ADUser `
    -SamAccountName "svc-admin" `
    -UserPrincipalName "svc-admin@testlab.local" `
    -AccountPassword $adminPass `
    -PasswordNeverExpires $true `
    -Enabled $true

Add-ADGroupMember -Identity "Domain Admins" -Members "svc-admin"
```

---

## Step 6 — Join IIS Server to Domain

Run on **IIS01** as Administrator.

```powershell
# Rename the machine first, then reboot
Rename-Computer -NewName "IIS01" -Force
Restart-Computer -Force
```

After reboot:

```powershell
# If the machine has multiple NICs, identify the internal lab interface first:
#   Get-NetAdapter | Select-Object Name, Status, MacAddress
# Then set $iface explicitly, e.g.:
#   $iface = "Ethernet 3"
$iface = (Get-NetAdapter | Where-Object Status -eq "Up").Name

# Set DC as primary DNS on the internal interface
Set-DnsClientServerAddress -InterfaceAlias $iface -ServerAddresses "10.12.10.10"

# Join domain and reboot
Add-Computer -DomainName "testlab.local" `
    -Credential (Get-Credential "TESTLAB\Administrator") `
    -Restart -Force
```

---

## Step 7 — Join Workstation to Domain

Run on **WS01** as Administrator.

```powershell
# Rename the machine first, then reboot
Rename-Computer -NewName "WS01" -Force
Restart-Computer -Force
```

After reboot:

```powershell
# If the machine has multiple NICs, identify the internal lab interface first:
#   Get-NetAdapter | Select-Object Name, Status, MacAddress
# Then set $iface explicitly, e.g.:
#   $iface = "Ethernet 3"
$iface = (Get-NetAdapter | Where-Object Status -eq "Up").Name

# Set static IP on the internal interface
New-NetIPAddress -InterfaceAlias $iface `
    -IPAddress "10.12.10.30" `
    -PrefixLength 24 `
    -DefaultGateway "10.12.10.1"

# Set DC as primary DNS on the internal interface
Set-DnsClientServerAddress -InterfaceAlias $iface -ServerAddresses "10.12.10.10"

# Verify WS01 can reach and resolve the domain before joining
ipconfig /all
Test-NetConnection 10.12.10.10 -Port 53
Test-NetConnection 10.12.10.10 -Port 88
Test-NetConnection 10.12.10.10 -Port 389
Resolve-DnsName testlab.local -Server 10.12.10.10
Resolve-DnsName _ldap._tcp.dc._msdcs.testlab.local -Server 10.12.10.10

# Join domain and reboot
Add-Computer -DomainName "testlab.local" `
    -Credential (Get-Credential "TESTLAB\Administrator") `
    -Restart -Force
```

---

## Step 8 — Workstation Local User Handling

Local users on **WS01** cannot be directly converted into domain users. A local account and a domain account are separate identities with different SIDs. Create a new domain user in AD, sign in with that domain user on WS01, migrate any required profile data, then remove the old local account if it is no longer needed.

Run on **DC01** to create a domain user:

```powershell
$userPass = ConvertTo-SecureString "l@bu53r.gr3atAga1n" -AsPlainText -Force

New-ADUser `
    -SamAccountName "labuser" `
    -UserPrincipalName "labuser@testlab.local" `
    -Name "labuser" `
    -AccountPassword $userPass `
    -PasswordNeverExpires $true `
    -Enabled $true
```

After creating the user, sign in on **WS01** as:

```text
TESTLAB\labuser
```

If the old local profile contains files that must be preserved, copy only the required user data from:

```text
C:\Users\<local-user>
```

to the new domain profile:

```text
C:\Users\<domain-user>
```

Common folders to migrate are `Desktop`, `Documents`, `Downloads`, and `Pictures`. Avoid copying the full `AppData` directory unless required.

Run on **WS01** to review local users:

```powershell
Get-LocalUser
```

Remove an old local user if it is no longer needed:

```powershell
Remove-LocalUser -Name "<local-user>"
```

Remove the old local profile directory if needed:

```powershell
Get-CimInstance Win32_UserProfile |
    Where-Object { $_.LocalPath -eq "C:\Users\<local-user>" } |
    Remove-CimInstance
```

Keep at least one local administrator account for recovery if domain authentication, DNS, or network connectivity breaks.

---

## Step 9 — Verify

```powershell
# Check domain accounts
Get-ADUser -Filter * | Select-Object SamAccountName, Enabled

# Check DNS zones
Get-DnsServerZone

# Confirm conditional forwarder
Get-DnsServerZone | Where-Object ZoneType -eq "Forwarder"

# Test internal A record resolution
Resolve-DnsName upload.testlab.local
Resolve-DnsName react.testlab.local
Resolve-DnsName ws01.testlab.local

# Confirm IIS01 and WS01 appear in AD
Get-ADComputer -Filter * | Select-Object Name, Enabled
```
