#include "service_installer.h"
#include <stdio.h>
#include <wchar.h>

BOOL InstallService(LPCWSTR exePath, LPCWSTR serviceName, LPCWSTR displayName, LPCWSTR description) {
    SC_HANDLE scManager = NULL;
    SC_HANDLE service = NULL;
    BOOL success = FALSE;
    
    // Open Service Control Manager
    scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scManager) {
        wprintf(L"OpenSCManager failed: %d\n", GetLastError());
        return FALSE;
    }
    
    // Create service
    service = CreateServiceW(
        scManager,
        serviceName,
        displayName ? displayName : serviceName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        exePath,
        NULL,   // No load ordering group
        NULL,   // No tag identifier
        NULL,   // No dependencies
        NULL,   // LocalSystem account
        NULL    // No password
    );
    
    if (!service) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            wprintf(L"Service '%s' already exists\n", serviceName);
        } else {
            wprintf(L"CreateService failed: %d\n", err);
        }
        goto cleanup;
    }
    
    wprintf(L"Service '%s' installed successfully\n", serviceName);
    
    // Set description if provided
    if (description && wcslen(description) > 0) {
        SERVICE_DESCRIPTIONW sd;
        sd.lpDescription = (LPWSTR)description;
        
        if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &sd)) {
            wprintf(L"Warning: Failed to set description: %d\n", GetLastError());
        }
    }
    
    success = TRUE;
    
cleanup:
    if (service) CloseServiceHandle(service);
    if (scManager) CloseServiceHandle(scManager);
    return success;
}

BOOL UninstallService(LPCWSTR serviceName) {
    SC_HANDLE scManager = NULL;
    SC_HANDLE service = NULL;
    BOOL success = FALSE;
    
    scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scManager) {
        wprintf(L"OpenSCManager failed: %d\n", GetLastError());
        return FALSE;
    }
    
    service = OpenServiceW(scManager, serviceName, SERVICE_STOP | DELETE);
    if (!service) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            wprintf(L"Service '%s' does not exist\n", serviceName);
        } else {
            wprintf(L"OpenService failed: %d\n", err);
        }
        goto cleanup;
    }
    
    // Try to stop service first
    SERVICE_STATUS status;
    if (QueryServiceStatus(service, &status)) {
        if (status.dwCurrentState != SERVICE_STOPPED) {
            wprintf(L"Stopping service '%s'...\n", serviceName);
            if (ControlService(service, SERVICE_CONTROL_STOP, &status)) {
                Sleep(1000);
            }
        }
    }
    
    // Delete service
    if (!DeleteService(service)) {
        wprintf(L"DeleteService failed: %d\n", GetLastError());
        goto cleanup;
    }
    
    wprintf(L"Service '%s' uninstalled successfully\n", serviceName);
    success = TRUE;
    
cleanup:
    if (service) CloseServiceHandle(service);
    if (scManager) CloseServiceHandle(scManager);
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
        wprintf(L"OpenService failed: %d\n", GetLastError());
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
    if (!scManager) {
        wprintf(L"OpenSCManager failed: %d\n", GetLastError());
        return FALSE;
    }
    
    service = OpenServiceW(scManager, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service) {
        wprintf(L"OpenService failed: %d\n", GetLastError());
        goto cleanup;
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
        wprintf(L"Service '%s' does not exist: %d\n", serviceName, GetLastError());
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
        
        // Get start type
        DWORD bytesNeeded = 0;
        QueryServiceConfigW(service, NULL, 0, &bytesNeeded);
        if (bytesNeeded > 0) {
            LPQUERY_SERVICE_CONFIGW config = (LPQUERY_SERVICE_CONFIGW)malloc(bytesNeeded);
            if (config && QueryServiceConfigW(service, config, bytesNeeded, &bytesNeeded)) {
                wprintf(L"Start Type: ");
                switch (config->dwStartType) {
                    case SERVICE_AUTO_START: wprintf(L"Automatic\n"); break;
                    case SERVICE_BOOT_START: wprintf(L"Boot\n"); break;
                    case SERVICE_DEMAND_START: wprintf(L"Manual\n"); break;
                    case SERVICE_DISABLED: wprintf(L"Disabled\n"); break;
                    case SERVICE_SYSTEM_START: wprintf(L"System\n"); break;
                    default: wprintf(L"Unknown\n");
                }
            }
            if (config) free(config);
        }
        
        found = TRUE;
    }
    
cleanup:
    if (service) CloseServiceHandle(service);
    if (scManager) CloseServiceHandle(scManager);
    return found;
}
