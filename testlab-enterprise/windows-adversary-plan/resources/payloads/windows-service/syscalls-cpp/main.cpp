#include "service_installer.h"
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <sddl.h>

// Check if running as administrator
BOOL IsAdministrator() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup)) {
        
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }
    
    return isAdmin;
}

void ShowHelp() {
    wprintf(L"NT Service Installer - Direct Syscalls Implementation\n");
    wprintf(L"======================================================\n\n");
    wprintf(L"Uses direct ntdll.dll calls to bypass user-mode API hooks\n\n");
    wprintf(L"USAGE:\n");
    wprintf(L"  NtServiceInstaller.exe <command> [arguments]\n\n");
    wprintf(L"COMMANDS:\n");
    wprintf(L"  install <exe-path> <service-name> [display-name] [description]\n");
    wprintf(L"      Install an executable as a Windows service\n");
    wprintf(L"      - exe-path: Full path to the executable file\n");
    wprintf(L"      - service-name: Name for the service (no spaces)\n");
    wprintf(L"      - display-name: (Optional) Display name for the service\n");
    wprintf(L"      - description: (Optional) Service description\n\n");
    wprintf(L"  uninstall <service-name>\n");
    wprintf(L"      Uninstall a Windows service\n\n");
    wprintf(L"  start <service-name>\n");
    wprintf(L"      Start a Windows service\n\n");
    wprintf(L"  stop <service-name>\n");
    wprintf(L"      Stop a Windows service\n\n");
    wprintf(L"  status <service-name>\n");
    wprintf(L"      Check the status of a Windows service\n\n");
    wprintf(L"  help\n");
    wprintf(L"      Show this help message\n\n");
    wprintf(L"EXAMPLES:\n");
    wprintf(L"  NtServiceInstaller.exe install \"C:\\MyApp\\app.exe\" MyService \"My App\"\n");
    wprintf(L"  NtServiceInstaller.exe start MyService\n");
    wprintf(L"  NtServiceInstaller.exe status MyService\n");
    wprintf(L"  NtServiceInstaller.exe stop MyService\n");
    wprintf(L"  NtServiceInstaller.exe uninstall MyService\n\n");
    wprintf(L"NOTE:\n");
    wprintf(L"  - This program must be run as Administrator\n");
    wprintf(L"  - Uses NT API to bypass advapi32.dll hooks\n");
    wprintf(L"  - Service may require reboot or SCM refresh to appear\n\n");
    wprintf(L"OPSEC:\n");
    wprintf(L"  - No CreateService/OpenSCManager calls during install\n");
    wprintf(L"  - Direct ntdll.dll registry manipulation\n");
    wprintf(L"  - Bypasses user-mode API hooks\n");
}

int wmain(int argc, wchar_t* argv[]) {
    // Check administrator privileges
    if (!IsAdministrator()) {
        wprintf(L"ERROR: This program must be run as Administrator\n");
        wprintf(L"Please run this application with administrator privileges\n");
        return 1;
    }
    
    if (argc < 2) {
        ShowHelp();
        return 0;
    }
    
    wchar_t* command = argv[1];
    
    // Help command
    if (_wcsicmp(command, L"help") == 0 || 
        _wcsicmp(command, L"-h") == 0 || 
        _wcsicmp(command, L"--help") == 0 || 
        _wcsicmp(command, L"?") == 0) {
        ShowHelp();
        return 0;
    }
    
    // Install command
    if (_wcsicmp(command, L"install") == 0) {
        if (argc < 4) {
            wprintf(L"ERROR: install command requires at least 2 arguments\n");
            wprintf(L"Usage: install <exe-path> <service-name> [display-name] [description]\n");
            return 1;
        }
        
        wchar_t* exePath = argv[2];
        wchar_t* serviceName = argv[3];
        wchar_t* displayName = (argc > 4) ? argv[4] : NULL;
        wchar_t* description = (argc > 5) ? argv[5] : NULL;
        
        return InstallService(exePath, serviceName, displayName, description) ? 0 : 1;
    }
    
    // Uninstall command
    if (_wcsicmp(command, L"uninstall") == 0) {
        if (argc < 3) {
            wprintf(L"ERROR: uninstall command requires service name\n");
            wprintf(L"Usage: uninstall <service-name>\n");
            return 1;
        }
        
        wchar_t* serviceName = argv[2];
        return UninstallService(serviceName) ? 0 : 1;
    }
    
    // Start command
    if (_wcsicmp(command, L"start") == 0) {
        if (argc < 3) {
            wprintf(L"ERROR: start command requires service name\n");
            wprintf(L"Usage: start <service-name>\n");
            return 1;
        }
        
        wchar_t* serviceName = argv[2];
        return StartServiceByName(serviceName) ? 0 : 1;
    }
    
    // Stop command
    if (_wcsicmp(command, L"stop") == 0) {
        if (argc < 3) {
            wprintf(L"ERROR: stop command requires service name\n");
            wprintf(L"Usage: stop <service-name>\n");
            return 1;
        }
        
        wchar_t* serviceName = argv[2];
        return StopServiceByName(serviceName) ? 0 : 1;
    }
    
    // Status command
    if (_wcsicmp(command, L"status") == 0) {
        if (argc < 3) {
            wprintf(L"ERROR: status command requires service name\n");
            wprintf(L"Usage: status <service-name>\n");
            return 1;
        }
        
        wchar_t* serviceName = argv[2];
        GetServiceStatusByName(serviceName);
        return 0;
    }
    
    // Unknown command
    wprintf(L"Unknown command: %s\n\n", command);
    ShowHelp();
    return 1;
}
