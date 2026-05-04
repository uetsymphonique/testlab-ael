#ifndef SERVICE_INSTALLER_H
#define SERVICE_INSTALLER_H

#include <windows.h>

// Service management functions
BOOL InstallService(LPCWSTR exePath, LPCWSTR serviceName, LPCWSTR displayName, LPCWSTR description);
BOOL UninstallService(LPCWSTR serviceName);
BOOL StartServiceByName(LPCWSTR serviceName);
BOOL StopServiceByName(LPCWSTR serviceName);
BOOL GetServiceStatusByName(LPCWSTR serviceName);

#endif // SERVICE_INSTALLER_H
