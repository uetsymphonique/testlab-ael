3.1 - Account Discovery: Domain Account (T1087.002) 
Noise
cmd.exe executed net user

3.2 - System Owner/User Discovery (T1033) 
Noise
cmd.exe executed whoami.exe

3.3 - System Network Configuration Discovery: Internet Connection Discovery (T1016.001) 
Noise
cmd.exe executed ping.exe with arugment google.com

3.4 - Ingress Tool Transfer (T1105) 
Noise
powershell.exe executed Invoke-WebRequest to download AdExplorer


3.5 - Valid Accounts: Domain Accounts (T1078.002) 
Noise
powershell.exe executed runas to review domain trust relationships


4.1 - Command and Scripting Interpreter: PowerShell (T1059.001) 
Noise
powershell.exe executed Get-PSDrive to gather disk usage


4.2 - Software Discovery: Security Software Discovery (T1518.001) 
Noise
cmd.exe executed netsh to verify active firewall rules on Windows host