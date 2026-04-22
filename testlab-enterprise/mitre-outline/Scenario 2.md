# Overview
Tập trung vào Doanh nghiệp (Enterprise Focused) - Gián điệp mạng (PRC Espionage Group)

Kịch bản này mô phỏng hành vi tấn công (tradecraft) của một nhóm gián điệp mạng có kỹ thuật tiên tiến, do nhà nước hậu thuẫn (cụ thể là đại diện cho các tác nhân từ Trung Quốc - PRC).

**Bối cảnh (Context):** Kịch bản đại diện cho các mối đe dọa thường trực (APT) nhắm vào các tổ chức trên toàn thế giới. Các nhóm này thường chia sẻ công cụ, kỹ thuật và cơ sở hạ tầng trong một hệ sinh thái tấn công được đầu tư mạnh mẽ, khiến việc quy kết trách nhiệm trở nên phức tạp.

**Cách thức hoạt động (Modus Operandi):** * **Xâm nhập ban đầu:** Kẻ tấn công thường vũ khí hóa các lỗ hổng _zero-day_ và _n-day_, khai thác các thiết bị vùng biên (edge devices) hướng ra internet hoặc cơ sở hạ tầng truy cập từ xa để tạo bàn đạp xâm nhập vào mạng lưới nạn nhân.

**Lẩn tránh và duy trì:** Chúng tận dụng khả năng thích ứng cao với môi trường, phát triển các payload tùy chỉnh, lạm dụng các dịch vụ đám mây hợp pháp và sử dụng triệt để các kỹ thuật "living-off-the-land" (dùng công cụ có sẵn của hệ điều hành) để trà trộn vào các hoạt động bình thường của doanh nghiệp, qua đó qua mặt các hệ thống giám sát.

**Trọng tâm đánh giá:** Kịch bản này không chỉ dừng lại ở một máy trạm (như Kịch bản 1) mà tập trung vào **một cuộc xâm nhập lẩn tránh nhắm vào toàn bộ quy mô doanh nghiệp**. Nó làm nổi bật việc khai thác cơ sở hạ tầng đa dạng (hybrid/cloud) và triển khai các công cụ mã nguồn mở/tùy chỉnh.

**Đối tượng giải pháp phù hợp nhất:** Kịch bản này được thiết kế để thử thách các giải pháp bảo mật toàn diện như:
- Các nền tảng XDR (Extended Detection and Response).
- Các giải pháp bảo vệ danh tính (Identity Protection).
- Các nhà cung cấp dịch vụ MDR/MSSP.
- Các nền tảng cung cấp khả năng hiển thị (visibility) trên toàn bộ không gian mạng của doanh nghiệp.
# Test Environment

| Component                 | Specification                                                                                                                                             |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| All Scenario 1 components | Windows Server 2022 domain controllers, file servers, web servers<br>Windows 11 Workstations<br>Exchange Server<br>pfSense firewall, network segmentation |
| Cloud Infrastructure      | AWS (Amazon Web Services)                                                                                                                                 |
| Virtual Machines          | AWS instances and/or additional virtualization platforms                                                                                                  |
| SSO/Indentity Provider    | Authentik (self-hosted IdP) + AWS IAM Identity Center — federated across both AWS organizations                                                           |
| Edge Devices & Appliances | Network edge devices and appliances                                                                                                                       |
| Linux Systems             | Ubuntu 24.04 (Noble Numbat)                                                                                                                               |
# Technique Scope

## Reconnaissance
+ T1589.001 - Gather Victim Identity Information: Credentials
+ T1595.002 - Active Scanning: Vulnerability Scanning

## Initial Access
+ T1078 - Valid Accounts
+ T1078.001 - Valid Accounts: Default Accounts
+ T1078.002 - Valid Accounts: Domain Accounts
+ T1078.003 - Valid Accounts: Local Accounts
+ T1078.004 - Valid Accounts: Cloud Accounts
+ T1133 - External Remote Services
+ T1190 - Exploit Public-Facing Application
## Execution
+ T1059.004 - Command and Scripting Interpreter: Unix Shell
+ T1059.009 - Command and Scripting Interpreter: Cloud API
+ T1203 - Exploitation for Client Execution
+ T1569.003 - System Services: Systemctl
+ T1651 - Cloud Administration Command
+ T1675 - ESXi Administration Command
## Persistence
+ T1037 - Boot or Logon Initialization Scripts
+ T1078 - Valid Accounts
+ T1078.001 - Valid Accounts: Default Accounts
+ T1078.002 - Valid Accounts: Domain Accounts
+ T1078.003 - Valid Accounts: Local Accounts
+ T1098.001 - Account Manipulation: Additional Cloud Credentials
+ T1098.003 - Account Manipulation: Additional Cloud Roles
+ T1098.004 - Account Manipulation: SSH Authorized Keys
+ T1098.007 - Account Manipulation: Additional Local or Domain Groups
+ T1112 - Modify Registry
+ T1133 - External Remote Services
+ T1136.001 - Create Account: Local Account
+ T1136.002 - Create Account: Domain Account
+ T1136.003 - Create Account: Cloud Account
+ T1505 - Server Software Component
+ T1505.003 - Server Software Component: Web Shell
+ T1543.002 - Create or Modify System Process: Systemd Service
## Privilege Escalation
+ T1037 - Boot or Logon Initialization Scripts
+ T1055 - Process Injection
+ T1055.009 - Process Injection: Proc Memory
+ T1078 - Valid Accounts
+ T1078.001 - Valid Accounts: Default Accounts
+ T1078.002 - Valid Accounts: Domain Accounts
+ T1078.003 - Valid Accounts: Local Accounts
+ T1484.001 - Domain or Tenant Policy Modification: Group Policy Modification
+ T1543.002 - Create or Modify System Process: Systemd Service
+ T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching
## Defense Evasion
+ T1006 - Direct Volume Access
+ T1027 - Obfuscated Files or Information
+ T1027.002 - Obfuscated Files or Information: Software Packing
+ T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools
+ T1027.008 - Obfuscated Files or Information: Stripped Payloads
+ T1027.009 - Obfuscated Files or Information: Embedded Payloads
+ T1027.010 - Obfuscated Files or Information: Command Obfuscation
+ T1027.013 - Obfuscated Files or Information: Encrypted/Encoded File
+ T1027.015 - Obfuscated Files or Information: Compression
+ T1027.016 - Obfuscated Files or Information: Junk Code Insertion
+ T1036 - Masquerading
+ T1036.003 - Masquerading: Rename Legitimate Utilities
+ T1036.004 - Masquerading: Masquerade Task or Service
+ T1036.005 - Masquerading: Match Legitimate Resource Name or Location
+ T1036.008 - Masquerading: Masquerade File Type
+ T1055 - Process Injection
+ T1055.009 - Process Injection: Proc Memory
+ T1070.002 - Indicator Removal: Clear Linux or Mac System Logs
+ T1070.003 - Indicator Removal: Clear Command History
+ T1070.004 - Indicator Removal: File Deletion
+ T1070.009 - Indicator Removal: Clear Persistence
+ T1078 - Valid Accounts
+ T1078.001 - Valid Accounts: Default Accounts
+ T1078.002 - Valid Accounts: Domain Accounts
+ T1078.003 - Valid Accounts: Local Accounts
+ T1112 - Modify Registry
+ T1140 - Deobfuscate/Decode Files or Information
+ T1222.002 - File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification
+ T1484.001 - Domain or Tenant Policy Modification: Group Policy Modification
+ T1497 - Virtualization/Sandbox Evasion
+ T1497.001 - Virtualization/Sandbox Evasion: System Checks
+ T1497.002 - Virtualization/Sandbox Evasion: User Activity Based Checks
+ T1550.004 - Use Alternate Authentication Material: Web Session Cookie
+ T1553.002 - Subvert Trust Controls: Code Signing
+ T1562.001 - Impair Defenses: Disable or Modify Tools
+ T1562.003 - Impair Defenses: Impair Command History Logging
+ T1562.004 - Impair Defenses: Disable or Modify System Firewall
+ T1562.006 - Impair Defenses: Indicator Blocking
+ T1562.007 - Impair Defenses: Disable or Modify Cloud Firewall
+ T1562.008 - Impair Defenses: Disable or Modify Cloud Logs
+ T1564.001 - Hide Artifacts: Hidden Files and Directories
+ T1564.002 - Hide Artifacts: Hidden Users
+ T1564.006 - Hide Artifacts: Run Virtual Instance
+ T1578.002 - Modify Cloud Compute Infrastructure: Create Cloud Instance
+ T1578.003 - Modify Cloud Compute Infrastructure: Delete Cloud Instance
+ T1620 - Reflective Code Loading
+ T1622 - Debugger Evasion
+ T1678 - Delay Execution

## Credential Access
+ T1003.003 - OS Credential Dumping: NTDS
+ T1003.005 - OS Credential Dumping: Cached Domain Credentials
+ T1040 - Network Sniffing
+ T1056.003 - Input Capture: Web Portal Capture
+ T1110 - Brute Force
+ T1552.001 - Unsecured Credentials: Credentials In Files
+ T1552.003 - Unsecured Credentials: Shell History
+ T1552.004 - Unsecured Credentials: Private Keys
+ T1557 - Adversary-in-the-Middle

## Discovery
+ T1007 - System Service Discovery
+ T1016 - System Network Configuration Discovery
+ T1018 - Remote System Discovery
+ T1033 - System Owner/User Discovery
+ T1046 - Network Service Discovery
+ T1049 - System Network Connections Discovery
+ T1057 - Process Discovery
+ T1069.001 - Permission Groups Discovery: Local Groups
+ T1069.002 - Permission Groups Discovery: Domain Groups
+ T1082 - System Information Discovery
+ T1083 - File and Directory Discovery
+ T1087.001 - Account Discovery: Local Account
+ T1087.002 - Account Discovery: Domain Account
+ T1087.003 - Account Discovery: Email Account
+ T1087.004 - Account Discovery: Cloud Account
+ T1135 - Network Share Discovery
+ T1217 - Browser Information Discovery
+ T1482 - Domain Trust Discovery
+ T1497.001 - Virtualization/Sandbox Evasion: System Checks
+ T1497.002 - Virtualization/Sandbox Evasion: User Activity Based Checks
+ T1518.001 - Software Discovery: Security Software Discovery
+ T1580 - Cloud Infrastructure Discovery
+ T1614.001 - System Location Discovery: System Language Discovery
+ T1619 - Cloud Storage Object Discovery
+ T1622 - Debugger Evasion
+ T1673 - Virtual Machine Discovery
+ T1680 - Local Storage Discovery

## Lateral Movement
+ T1021.001 - Remote Services: Remote Desktop Protocol
+ T1021.004 - Remote Services: SSH
+ T1021.007 - Remote Services: Cloud Services
+ T1550.004 - Use Alternate Authentication Material: Web Session Cookie
+ T1570 - Lateral Tool Transfer

## Collection
+ T1005 - Data from Local System
+ T1039 - Data from Network Shared Drive
+ T1074.001 - Data Staged: Local Data Staging
+ T1074.002 - Data Staged: Remote Data Staging
+ T1114.001 - Email Collection: Local Email Collection
+ T1114.002 - Email Collection: Remote Email Collection
+ T1119 - Automated Collection
+ T1213.003 - Data from Information Repositories: Code Repositories
+ T1213.006 - Data from Information Repositories: Databases
+ T1530 - Data from Cloud Storage
+ T1560 - Archive Collected Data
+ T1560.001 - Archive Collected Data: Archive via Utility
+ T1560.002 - Archive Collected Data: Archive via Library
+ T1560.003 - Archive Collected Data: Archive via Custom Method

## Command and Control
+ T1008 - Fallback Channels
+ T1071.001 - Application Layer Protocol: Web Protocols
+ T1071.002 - Application Layer Protocol: File Transfer Protocols
+ T1071.004 - Application Layer Protocol: DNS
+ T1090 - Proxy
+ T1090.001 - Proxy: Internal Proxy
+ T1090.002 - Proxy: External Proxy
+ T1090.003 - Proxy: Multi-hop Proxy
+ T1095 - Non-Application Layer Protocol
+ T1102 - Web Service
+ T1105 - Ingress Tool Transfer
+ T1132.001 - Data Encoding: Standard Encoding
+ T1132.002 - Data Encoding: Non-Standard Encoding
+ T1219 - Remote Access Tools
+ T1219.002 - Remote Access Tools: Remote Desktop Software
+ T1568 - Dynamic Resolution
+ T1571 - Non-Standard Port
+ T1572 - Protocol Tunneling
+ T1573.001 - Encrypted Channel: Symmetric Cryptography
+ T1573.002 - Encrypted Channel: Asymmetric Cryptography

## Exfiltration
+ T1020 - Automated Exfiltration
+ T1030 - Data Transfer Size Limits
+ T1041 - Exfiltration Over C2 Channel
+ T1048 - Exfiltration Over Alternative Protocol
+ T1048.001 - Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol
+ T1048.002 - Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
+ T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
+ T1537 - Transfer Data to Cloud Account
+ T1567 - Exfiltration Over Web Service
+ T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage

## Impact
+ T1531 - Account Access Removal
