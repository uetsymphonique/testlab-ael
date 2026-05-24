@echo off
REM Run from x64 Native Tools Command Prompt for VS
REM Phase 2: advapi32.lib dropped — SCM functions resolved dynamically via GetProcAddress
cl /O2 /MT /W4 impact.c aes.c /Fe:impact.exe /link ole32.lib
