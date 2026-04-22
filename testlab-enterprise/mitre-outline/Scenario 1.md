# Overview

Kịch bản này được thiết kế để mô phỏng một chiến dịch **Phần mềm tội phạm dưới dạng dịch vụ (Crimeware-as-a-Service)**, phản ánh nền kinh tế ngầm phân tầng và dựa trên vai trò của tội phạm mạng. Kịch bản làm rõ việc các tác nhân chuyên biệt hợp tác qua từng giai đoạn khác nhau của cuộc tấn công thay vì hoạt động như một nhóm thống nhất.
Quá trình xâm nhập diễn ra theo vòng đời như sau:
- **Khởi đầu:** Sử dụng các kỹ thuật xã hội (social engineering) có mục tiêu để đánh cắp thông tin xác thực.
- **Chuyển giao:** Quyền truy cập bị đánh cắp sau đó được tiền tệ hóa và chuyển giao cho các tác nhân hạ nguồn để chúng tiến hành thỏa hiệp môi trường nạn nhân.
- **Tiến triển và Phá hoại:** Chuỗi tấn công tập trung vào điểm cuối đi qua các bước thỏa hiệp môi trường, di chuyển ngang (lateral movement), trích xuất dữ liệu (data exfiltration), và cuối cùng là gây ra các tác động phá hoại (destructive impact).
- **Phương thức lẩn tránh:** Xuyên suốt quá trình này, kẻ tấn công áp dụng triệt để các kỹ thuật living-off-the-land nhằm trốn tránh các hệ thống phát hiện.
Sự thương mại hóa này đã làm cho các vụ xâm nhập mạng diễn ra nhanh hơn, khó quy kết hơn và dễ tiếp cận hơn đối với nhiều loại tội phạm.
# Test Environment

**Cơ sở hạ tầng Thử nghiệm** Để đánh giá hiệu quả, Kịch bản 1 được thực thi trên một hệ thống mạng thử nghiệm chuyên biệt (Detections Range) tập trung vào môi trường điểm cuối. Cơ sở hạ tầng mô phỏng này bao gồm:

| Component                         | Specification                                                          |
| --------------------------------- | ---------------------------------------------------------------------- |
| Domain Controllers & File Servers | Windows Server 2022                                                    |
| Web Servers                       | Windows Server 2022                                                    |
| Workstations                      | Windows 11 Enterprise                                                  |
| Email Infrastructure              | Exchange Server 2019                                                   |
| Network Firewall                  | pfSense or Open Source                                                 |
| Network Segmentation              | Realistic segmentation — DMZ, internal workstation zones, server zones |
# Technique Scope
## Reconnaissance
- T1592.001 - Gather Victim Host Information: Hardware
- T1592.002 - Gather Victim Host Information: Software
## Initial Access
- T1078 - Valid Accounts
- T1078.001 - Valid Accounts: Default Accounts
- T1078.002 - Valid Accounts: Domain Accounts
- T1078.003 - Valid Accounts: Local Accounts
- T1133 - External Remote Services
- T1189 - Drive-by Compromise
## Execution
- T1047 - Windows Management Instrumentation
- T1053.005 - Scheduled Task/Job: Scheduled Task
- T1059 - Command and Scripting Interpreter
- T1059.001 - Command and Scripting Interpreter: PowerShell
- T1059.003 - Command and Scripting Interpreter: Windows Command Shell
- T1059.005 - Command and Scripting Interpreter: Visual Basic
- T1059.007 - Command and Scripting Interpreter: JavaScript
- T1059.010 - Command and Scripting Interpreter: AutoHotKey & AutoIT
- T1106 - Native API
- T1204 - User Execution
- T1204.001 - User Execution: Malicious Link
- T1204.002 - User Execution: Malicious File
- T1204.004 - User Execution: Malicious Copy and Paste
- T1569.002 - System Services: Service Execution
## Persistence
- T1037.001 - Boot or Logon Initialization Scripts: Logon Script (Windows)
- T1037.003 - Boot or Logon Initialization Scripts: Network Logon Script
- T1037.005 - Boot or Logon Initialization Scripts: Startup Items
- T1078 - Valid Accounts
- T1078.001 - Valid Accounts: Default Accounts
- T1078.002 - Valid Accounts: Domain Accounts
- T1078.003 - Valid Accounts: Local Accounts
- T1098 - Account Manipulation
- T1098.007 - Account Manipulation: Additional Local or Domain Groups
- T1112 - Modify Registry
- T1133 - External Remote Services
- T1136.001 - Create Account: Local Account
- T1136.002 - Create Account: Domain Account
- T1543.003 - Create or Modify System Process: Windows Service
- T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription
- T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL
- T1574.001 - Hijack Execution Flow: DLL
## Privilege Escalation
- T1037.001 - Boot or Logon Initialization Scripts: Logon Script (Windows)
- T1037.003 - Boot or Logon Initialization Scripts: Network Logon Script
- T1037.005 - Boot or Logon Initialization Scripts: Startup Items
- T1055 - Process Injection
- T1055.001 - Process Injection: Dynamic-link Library Injection
- T1055.002 - Process Injection: Portable Executable Injection
- T1055.012 - Process Injection: Process Hollowing
- T1078 - Valid Accounts
- T1078.001 - Valid Accounts: Default Accounts
- T1078.002 - Valid Accounts: Domain Accounts
- T1078.003 - Valid Accounts: Local Accounts
- T1134.001 - Access Token Manipulation: Token Impersonation/Theft
- T1134.002 - Access Token Manipulation: Create Process with Token
- T1134.003 - Access Token Manipulation: Make and Impersonate Token
- T1134.004 - Access Token Manipulation: Parent PID Spoofing
- T1543.003 - Create or Modify System Process: Windows Service
- T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription
- T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL
- T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control
- T1574.001 - Hijack Execution Flow: DLL
## Defense Evasion
- T1006 - Direct Volume Access
- T1027 - Obfuscated Files or Information
- T1027.002 - Obfuscated Files or Information: Software Packing
- T1027.004 - Obfuscated Files or Information: Compile After Delivery
- T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools
- T1027.006 - Obfuscated Files or Information: HTML Smuggling
- T1027.007 - Obfuscated Files or Information: Dynamic API Resolution
- T1027.008 - Obfuscated Files or Information: Stripped Payloads
- T1027.009 - Obfuscated Files or Information: Embedded Payloads
- T1027.010 - Obfuscated Files or Information: Command Obfuscation
- T1027.013 - Obfuscated Files or Information: Encrypted/Encoded File
- T1027.015 - Obfuscated Files or Information: Compression
- T1027.016 - Obfuscated Files or Information: Junk Code Insertion
- T1036 - Masquerading
- T1036.003 - Masquerading: Rename Legitimate Utilities
- T1036.004 - Masquerading: Masquerade Task or Service
- T1036.005 - Masquerading: Match Legitimate Resource Name or Location
- T1036.008 - Masquerading: Masquerade File Type
- T1055 - Process Injection
- T1055.001 - Process Injection: Dynamic-link Library Injection
- T1055.002 - Process Injection: Portable Executable Injection
- T1055.012 - Process Injection: Process Hollowing
- T1070.001 - Indicator Removal: Clear Windows Event Logs
- T1070.003 - Indicator Removal: Clear Command History
- T1070.004 - Indicator Removal: File Deletion
- T1070.005 - Indicator Removal: Network Share Connection Removal
- T1070.009 - Indicator Removal: Clear Persistence
- T1078 - Valid Accounts
- T1078.001 - Valid Accounts: Default Accounts
- T1078.002 - Valid Accounts: Domain Accounts
- T1078.003 - Valid Accounts: Local Accounts
- T1112 - Modify Registry
- T1134.001 - Access Token Manipulation: Token Impersonation/Theft
- T1134.002 - Access Token Manipulation: Create Process with Token
- T1134.003 - Access Token Manipulation: Make and Impersonate Token
- T1134.004 - Access Token Manipulation: Parent PID Spoofing
- T1140 - Deobfuscate/Decode Files or Information
- T1202 - Indirect Command Execution
- T1218.005 - System Binary Proxy Execution: Mshta
- T1218.010 - System Binary Proxy Execution: Regsvr32
- T1218.011 - System Binary Proxy Execution: Rundll32
- T1218.013 - System Binary Proxy Execution: Mavinject
- T1222.001 - File and Dirctory Permissions Modification: Windows File and Directory Permissions Modification
- T1480.001 - Execution Guardrails: Environmental Keying
- T1480.002 - Execution Guardrails: Mutual Exclusion
- T1484.001 - Domain or Tenant Policy Modification: Group Policy Modification
- T1497 - Virtualization/Sandbox Evasion
- T1497.001 - Virtualization/Sandbox Evasion: System Checks
- T1497.002 - Virtualization/Sandbox Evasion: User Activity Based Checks
- T1553.002 - Subvert Trust Controls: Code Signing
- T1562.001 - Impair Defenses: Disable or Modify Tools
- T1562.002 - Impair Defenses: Disable Windows Event Logging
- T1562.003 - Impair Defenses: Impair Command History Logging
- T1562.004 - Impair Defenses: Disable or Modify System Firewall
- T1562.006 - Impair Defenses: Indicator Blocking
- T1564.001 - Hide Artifacts: Hidden Files and Directories
- T1564.002 - Hide Artifacts: Hidden Users
- T1564.003 - Hide Artifacts: Hidden Window
- T1564.010 - Hide Artifacts: Process Argument Spoofing
- T1574.001 - Hijack Execution Flow: DLL
- T1620 - Reflective Code Loading
- T1622 - Debugger Evasion
- T1678 - Delay Execution
- T1679 - Selective Exclusion
## Credential Access
- T1003.001 - OS Credential Dumping: LSASS Memory
- T1003.005 - OS Credential Dumping: Cached Domain Credentials
- T1539 - Steal Web Session Cookie
- T1552.001 - Unsecured Credentials: Credentials In Files
- T1555.003 - Credentials from Password Stores: Credentials from Web Browsers
- T1555.004 - Credentials from Password Stores: Windows Credential Manager
- T1555.005 - Credentials from Password Stores: Password Managers
## Discovery
- T1007 - System Service Discovery
- T1012 - Query Registry
- T1018 - Remote System Discovery
- T1033 - System Owner/User Discovery
- T1057 - Process Discovery
- T1069.001 - Permission Groups Discovery: Local Groups
- T1069.002 - Permission Groups Discovery: Domain Groups
- T1082 - System Information Discovery
- T1083 - File and Directory Discovery
- T1087.001 - Account Discovery: Local Account
- T1087.002 - Account Discovery: Domain Account
- T1135 - Network Share Discovery
- T1217 - Browser Information Discovery
- T1482 - Domain Trust Discovery
- T1497.001 - Virtualization/Sandbox Evasion: System Checks
- T1497.002 - Virtualization/Sandbox Evasion: User Activity Based Checks
- T1518.001 - Software Discovery: Security Software Discovery
- T1614.001 - System Location Discovery: System Language Discovery
- T1622 - Debugger Evasion
- T1680 - Local Storage Discovery
## Lateral Movement
- T1021.001 - Remote Services: Remote Desktop Protocol
- T1021.002 - Remote Services: SMB/Windows Admin Shares
- T1021.004 - Remote Services: SSH
- T1021.006 - Remote Services: Windows Remote Management
- T1550.002 - Use Alternate Authentication Material: Pass the Hash
- T1550.004 - Use Alternate Authentication Material: Web Session Cookie
- T1570 - Lateral Tool Transfer
## Collection
- T1005 - Data from Local System
- T1039 - Data from Network Shared Drive
- T1074.001 - Data Staged: Local Data Staging
- T1113 - Screen Capture
- T1115 - Clipboard Data
- T1119 - Automated Collection
- T1560 - Archive Collected Data
- T1560.001 - Archive Collected Data: Archive via Utility
- T1560.002 - Archive Collected Data: Archive via Library
- T1560.003 - Archive Collected Data: Archive via Custom Method
## Command and Control
- T1071.001 - Application Layer Protocol: Web Protocols
- T1105 - Ingress Tool Transfer
- T1132.001 - Data Encoding: Standard Encoding
- T1132.002 - Data Encoding: Non-Standard Encoding
- T1571 - Non-Standard Port
- T1573.001 - Encrypted Channel: Symmetric Cryptography
- T1573.002 - Encrypted Channel: Asymmetric Cryptography
## Exfiltration
- T1020 - Automated Exfiltration
- T1030 - Data Transfer Size Limits
- T1041 - Exfiltration Over C2 Channel
- T1048 - Exfiltration Over Alternative Protocol
- T1048.001 - Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol
- T1048.002 - Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
- T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
## Impact
- T1486 - Data Encrypted for Impact
- T1489 - Service Stop
- T1490 - Inhibit System Recovery
- T1491.001 - Defacement: Internal Defacement
- T1529 - System Shutdown/Reboot
- T1561.001 - Disk Wipe: Disk Content Wipe
