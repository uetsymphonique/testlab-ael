#include "service_installer.h"
#include "nt_api.h"
#include <stdio.h>
#include <wchar.h>

// Helper to set registry DWORD value
static BOOL SetRegistryDWord(HANDLE keyHandle, LPCWSTR valueName, DWORD value) {
    UNICODE_STRING valueNameUs;
    InitUnicodeString(&valueNameUs, valueName);
    
    NTSTATUS status = NtSetValueKey(
        keyHandle,
        &valueNameUs,
        0,
        REG_DWORD,
        &value,
        sizeof(DWORD)
    );
    
    if (status != STATUS_SUCCESS) {
        wprintf(L"Failed to set %s: 0x%X\n", valueName, status);
        return FALSE;
    }
    return TRUE;
}

// Helper to set registry string value
static BOOL SetRegistryString(HANDLE keyHandle, LPCWSTR valueName, LPCWSTR value) {
    UNICODE_STRING valueNameUs;
    InitUnicodeString(&valueNameUs, valueName);
    
    SIZE_T length = (wcslen(value) + 1) * sizeof(WCHAR);
    
    NTSTATUS status = NtSetValueKey(
        keyHandle,
        &valueNameUs,
        0,
        REG_SZ,
        (PVOID)value,
        (ULONG)length
    );
    
    if (status != STATUS_SUCCESS) {
        wprintf(L"Failed to set %s: 0x%X\n", valueName, status);
        return FALSE;
    }
    return TRUE;
}

BOOL InstallService(LPCWSTR exePath, LPCWSTR serviceName, LPCWSTR displayName, LPCWSTR description) {
    HANDLE servicesKey = NULL;
    HANDLE serviceKey = NULL;
    NTSTATUS status;
    ULONG disposition;
    BOOL success = FALSE;
    
    if (!InitNtFunctions()) {
        wprintf(L"Failed to initialize NT functions\n");
        return FALSE;
    }
    
    // Open Services registry key
    UNICODE_STRING servicesPath;
    InitUnicodeString(&servicesPath, SERVICES_KEY_PATH);
    
    OBJECT_ATTRIBUTES servicesOa;
    InitObjectAttributes(&servicesOa, &servicesPath, OBJ_CASE_INSENSITIVE, NULL);
    
    status = NtOpenKey(&servicesKey, KEY_CREATE_SUB_KEY, &servicesOa);
    if (status != STATUS_SUCCESS) {
        wprintf(L"Failed to open Services key: 0x%X\n", status);
        return FALSE;
    }
    
    // Create service subkey
    UNICODE_STRING serviceNameUs;
    InitUnicodeString(&serviceNameUs, serviceName);
    
    OBJECT_ATTRIBUTES serviceOa;
    InitObjectAttributes(&serviceOa, &serviceNameUs, OBJ_CASE_INSENSITIVE, servicesKey);
    
    status = NtCreateKey(
        &serviceKey,
        KEY_ALL_ACCESS,
        &serviceOa,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        &disposition
    );
    
    if (status != STATUS_SUCCESS) {
        wprintf(L"Failed to create service key: 0x%X\n", status);
        goto cleanup;
    }
    
    wprintf(L"Service key created (disposition: %d)\n", disposition);
    
    // Set service parameters
    if (!SetRegistryDWord(serviceKey, L"Type", SERVICE_WIN32_OWN_PROCESS)) goto cleanup;
    if (!SetRegistryDWord(serviceKey, L"Start", SERVICE_AUTO_START)) goto cleanup;
    if (!SetRegistryDWord(serviceKey, L"ErrorControl", SERVICE_ERROR_NORMAL)) goto cleanup;
    if (!SetRegistryString(serviceKey, L"ImagePath", exePath)) goto cleanup;
    if (!SetRegistryString(serviceKey, L"DisplayName", displayName ? displayName : serviceName)) goto cleanup;
    if (!SetRegistryString(serviceKey, L"ObjectName", L"LocalSystem")) goto cleanup;
    
    if (description && wcslen(description) > 0) {
        SetRegistryString(serviceKey, L"Description", description);
    }
    
    wprintf(L"Service '%s' installed successfully via NT syscalls\n", serviceName);
    wprintf(L"Note: Service requires system reboot or manual SCM refresh to appear\n");
    
    success = TRUE;
    
cleanup:
    if (serviceKey) NtClose(serviceKey);
    if (servicesKey) NtClose(servicesKey);
    return success;
}

BOOL UninstallService(LPCWSTR serviceName) {
    HANDLE servicesKey = NULL;
    HANDLE serviceKey = NULL;
    NTSTATUS status;
    BOOL success = FALSE;
    
    if (!InitNtFunctions()) {
        wprintf(L"Failed to initialize NT functions\n");
        return FALSE;
    }
    
    // Try to stop service first (using ServiceController fallback)
    StopServiceByName(serviceName);
    
    // Open Services key
    UNICODE_STRING servicesPath;
    InitUnicodeString(&servicesPath, SERVICES_KEY_PATH);
    
    OBJECT_ATTRIBUTES servicesOa;
    InitObjectAttributes(&servicesOa, &servicesPath, OBJ_CASE_INSENSITIVE, NULL);
    
    status = NtOpenKey(&servicesKey, KEY_ENUMERATE_SUB_KEYS, &servicesOa);
    if (status != STATUS_SUCCESS) {
        wprintf(L"Failed to open Services key: 0x%X\n", status);
        return FALSE;
    }
    
    // Open service subkey
    UNICODE_STRING serviceNameUs;
    InitUnicodeString(&serviceNameUs, serviceName);
    
    OBJECT_ATTRIBUTES serviceOa;
    InitObjectAttributes(&serviceOa, &serviceNameUs, OBJ_CASE_INSENSITIVE, servicesKey);
    
    status = NtOpenKey(&serviceKey, DELETE, &serviceOa);
    if (status != STATUS_SUCCESS) {
        if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
            wprintf(L"Service '%s' does not exist\n", serviceName);
        } else {
            wprintf(L"Failed to open service key: 0x%X\n", status);
        }
        goto cleanup;
    }
    
    // Delete the key
    status = NtDeleteKey(serviceKey);
    if (status != STATUS_SUCCESS) {
        wprintf(L"Failed to delete service key: 0x%X\n", status);
        goto cleanup;
    }
    
    wprintf(L"Service '%s' uninstalled successfully via NT syscalls\n", serviceName);
    success = TRUE;
    
cleanup:
    if (serviceKey) NtClose(serviceKey);
    if (servicesKey) NtClose(servicesKey);
    return success;
}

BOOL StartServiceByName(LPCWSTR serviceName) {
    SC_HANDLE scManager = NULL;
    SC_HANDLE service = NULL;
    BOOL success = FALSE;
    
    scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scManager) {
        wprintf(L"OpenSCManager failed: %d\n", GetLastError());
        return FALSE;
    }
    
    service = OpenServiceW(scManager, serviceName, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            wprintf(L"Service '%s' not found (may need reboot)\n", serviceName);
        } else {
            wprintf(L"OpenService failed: %d\n", err);
        }
        goto cleanup;
    }
    
    SERVICE_STATUS status;
    if (QueryServiceStatus(service, &status)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
            wprintf(L"Service '%s' is already running\n", serviceName);
            success = TRUE;
            goto cleanup;
        }
    }
    
    wprintf(L"Starting service '%s'...\n", serviceName);
    if (!StartServiceW(service, 0, NULL)) {
        wprintf(L"StartService failed: %d\n", GetLastError());
        goto cleanup;
    }
    
    // Wait for service to start
    Sleep(1000);
    if (QueryServiceStatus(service, &status)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
            wprintf(L"Service '%s' started successfully\n", serviceName);
            success = TRUE;
        } else {
            wprintf(L"Service state: %d\n", status.dwCurrentState);
        }
    }
    
cleanup:
    if (service) CloseServiceHandle(service);
    if (scManager) CloseServiceHandle(scManager);
    return success;
}

BOOL StopServiceByName(LPCWSTR serviceName) {
    SC_HANDLE scManager = NULL;
    SC_HANDLE service = NULL;
    BOOL success = FALSE;
    
    scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scManager) return FALSE;
    
    service = OpenServiceW(scManager, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scManager);
        return FALSE;
    }
    
    SERVICE_STATUS status;
    if (QueryServiceStatus(service, &status)) {
        if (status.dwCurrentState == SERVICE_STOPPED) {
            wprintf(L"Service '%s' is already stopped\n", serviceName);
            success = TRUE;
            goto cleanup;
        }
    }
    
    wprintf(L"Stopping service '%s'...\n", serviceName);
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        wprintf(L"ControlService failed: %d\n", GetLastError());
        goto cleanup;
    }
    
    // Wait for service to stop
    Sleep(1000);
    if (QueryServiceStatus(service, &status)) {
        if (status.dwCurrentState == SERVICE_STOPPED) {
            wprintf(L"Service '%s' stopped successfully\n", serviceName);
            success = TRUE;
        }
    }
    
cleanup:
    if (service) CloseServiceHandle(service);
    if (scManager) CloseServiceHandle(scManager);
    return success;
}

BOOL GetServiceStatusByName(LPCWSTR serviceName) {
    SC_HANDLE scManager = NULL;
    SC_HANDLE service = NULL;
    BOOL found = FALSE;
    
    scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scManager) {
        wprintf(L"OpenSCManager failed: %d\n", GetLastError());
        return FALSE;
    }
    
    service = OpenServiceW(scManager, serviceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!service) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            wprintf(L"Service '%s' does not exist in SCM\n", serviceName);
            wprintf(L"Note: Service may exist in registry but not yet loaded by SCM\n");
        } else {
            wprintf(L"OpenService failed: %d\n", err);
        }
        goto cleanup;
    }
    
    SERVICE_STATUS status;
    if (QueryServiceStatus(service, &status)) {
        wprintf(L"Service Name: %s\n", serviceName);
        wprintf(L"Status: ");
        switch (status.dwCurrentState) {
            case SERVICE_STOPPED: wprintf(L"Stopped\n"); break;
            case SERVICE_START_PENDING: wprintf(L"Start Pending\n"); break;
            case SERVICE_STOP_PENDING: wprintf(L"Stop Pending\n"); break;
            case SERVICE_RUNNING: wprintf(L"Running\n"); break;
            case SERVICE_CONTINUE_PENDING: wprintf(L"Continue Pending\n"); break;
            case SERVICE_PAUSE_PENDING: wprintf(L"Pause Pending\n"); break;
            case SERVICE_PAUSED: wprintf(L"Paused\n"); break;
            default: wprintf(L"Unknown (%d)\n", status.dwCurrentState);
        }
        wprintf(L"Service Type: Win32 Own Process\n");
        found = TRUE;
    }
    
cleanup:
    if (service) CloseServiceHandle(service);
    if (scManager) CloseServiceHandle(scManager);
    return found;
}
