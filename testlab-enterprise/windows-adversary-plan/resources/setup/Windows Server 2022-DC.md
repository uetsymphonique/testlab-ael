# Lab Setup — Windows Server 2022 Domain Controller

## Environment Overview

| Role | Hostname | IP |
| - | - | - |
| Domain Controller | `DC01` | `10.12.10.10` |
| IIS Server | `IIS01` | `10.12.10.20` |

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

## Step 7 — Verify

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

# Confirm IIS01 appears in AD
Get-ADComputer -Filter * | Select-Object Name, Enabled
```
