# ReflectDump — Flow

**Entry:** `main()` in `Source.cpp`  ·  **Artifact summary:** lsass.exe forked via `RtlCreateProcessReflection` → full-memory minidump captured in heap buffer → XOR-encrypted → written to `%TEMP%\~DFxxxx.tmp`

| # | Behavior (`actor action artifact`) | Artifact [class] → consumed by | Tactic / TID — Technique Name | Context (baseline) |
|---|---|---|---|---|
| 1 | ReflectDump.exe queries own token elevation | — [no-artifact] → #2 | — | token self-query on current process; standard pre-flight check |
| 2 | ReflectDump.exe allocates 75 MB heap buffer | heap region [memory] → #8 | — | large heap commit before any cross-process activity |
| 3 | ReflectDump.exe enumerates running processes to locate lsass.exe | lsass PID [process] → #4 | Discovery / T1057 — Process Discovery | EnumProcesses + PROCESS_QUERY_LIMITED_INFORMATION per PID; avoids Toolhelp32 snapshot |
| 4 | ReflectDump.exe opens handle to lsass.exe with REFLECT_ACCESS mask (~0x4FA) | LSASS process handle [process] → #6 | Credential Access / T1003.001 — OS Credential Dumping: LSASS Memory | GrantedAccess ~0x4FA, not 0x1FFFFF; Sysmon EventCode=10 on lsass.exe |
| 5 | ReflectDump.exe resolves RtlCreateProcessReflection from ntdll.dll via runtime char-array | — [no-artifact] → #6 | Defense Evasion / T1027.007 — Obfuscated Files or Information: Dynamic API Resolution | API name built char-by-char; absent from static IAT |
| 6a | ReflectDump.exe forks lsass.exe into a suspended reflection process via RtlCreateProcessReflection | reflection process handle + PID [process] → #8, #10 | Execution / T1106 — Native API | undocumented ntdll API; new PID appears as child process creation under lsass.exe (Sysmon EventCode=1) |
| 6b | ReflectDump.exe forks lsass.exe into a suspended reflection process via RtlCreateProcessReflection | reflection process handle + PID [process] → #8, #10 | Credential Access / T1003.001 — OS Credential Dumping: LSASS Memory | undocumented ntdll API; new PID appears as child process creation under lsass.exe (Sysmon EventCode=1) |
| 7 | ReflectDump.exe loads dbghelp.dll and resolves MiniDumpWriteDump via runtime char-array | dbghelp.dll module load [process] → #8 | Defense Evasion / T1027.007 — Obfuscated Files or Information: Dynamic API Resolution | dbghelp.dll absent from static IAT; runtime load observable as module-load event (Sysmon EventCode=7) |
| 8 | ReflectDump.exe dumps reflection process memory into heap buffer via MiniDumpWithFullMemory callback | dump bytes in heap buffer [memory] → #9 | Credential Access / T1003.001 — OS Credential Dumping: LSASS Memory | dump handle targets reflection PID, not lsass.exe PID; IoWriteAllCallback intercepts all I/O — no file handle passed to MiniDumpWriteDump |
| 9 | ReflectDump.exe writes XOR-encrypted dump buffer to %TEMP%\~DFxxxx.tmp | ~DFxxxx.tmp encrypted dump file [file] | Defense Evasion / T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File | linear XOR strips MDMP magic bytes; filename matches MS Office/shell temp pattern |
| 10 | ReflectDump.exe terminates the reflection process via TerminateProcess | process exit event [process] | Execution / T1106 — Native API | cleanup of clone via existing handle; Sysmon EventCode=5 on reflection PID |
