> Initial Access -> Execution (-> Command and Control) (-> Persistence) (can be combined with Defense Evasion)
# Summarry
Attacker -> upload webshell to `upload.testlab.local` via file upload -> execute webshell -> controll IIS server via webshell
         -> upload dnscat2 client to IIS server -> upload smuggled payload via file upload (This HTML file will be used to trick users into downloading a dropper (could be .hta, .lnk, or macro in an Office file...)) -> dropper downloads and executes dnscat2 client on a workstation in the lab
         -> exploit React2Shell in `react.testlab.local` to RCE trên IIS server (alternative way to gain access to IIS server)
# Initial Access + Execution
## Description
Exploit in IIS Web Server, two websites:
+ `react.testlab.local`: forward to a NodeJS + React + NextJS web
+ `upload.testlab.local`: has upload file feature, can serve aspx (-> upload webshell) and .hta/.sct (Drive-by Compromise)

## Vectors
### React2Shell
Technique: T1190 - Exploit Public-Facing Application

### Upload Webshell
Technique: T1190 - Exploit Public-Facing Application, T1505.003 - Server Software Component: Web Shell, T1059.001 - Command and Scripting Interpreter: PowerShell

Description: Upload webshell to the server

[Procedure](Procedures/T1190.md#atomic-test-2-webshell-deployment-via-file-upload)
### Drive-by Compromise + HTML Smuggling
This step can be approached in several ways:
+ Use .hta to stage payload and execute
+ Use macro in an Office file to perform the next action
+ Use a .lnk file to perform the next action

# Command and Control

## Vectors

### dnscat2
Technique: T1071.004 - Application Layer Protocol: DNS
Additionally, it will be used in combination with the following techniques:
+ T1573.001 - Encrypted Channel: Symmetric Cryptography (using key to encrypt C2 traffic)
+ T1055 - Process Injection (Process Herpaderping, using to inject payload and legitimate process)
