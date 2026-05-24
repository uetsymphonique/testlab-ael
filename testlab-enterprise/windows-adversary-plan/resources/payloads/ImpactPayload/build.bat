@echo off
REM Run from x64 Native Tools Command Prompt for VS
cl /O2 /MT /W4 impact.c aes.c /Fe:impact.exe /link advapi32.lib ole32.lib
