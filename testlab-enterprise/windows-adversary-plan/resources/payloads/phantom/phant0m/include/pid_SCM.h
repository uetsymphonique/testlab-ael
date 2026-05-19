#pragma once

DWORD GetPIDFromSCManager() {

	printf("[*] Querying Service Control Manager...\n");

	SC_HANDLE schSCManager, schService;
	SERVICE_STATUS_PROCESS ssProcess = {};
	DWORD dwBytesNeeded = 0;

	schSCManager = OpenSCManagerA(NULL, NULL, SERVICE_QUERY_STATUS);

	if (NULL == schSCManager) {

		printf("[!] SCM connection failed (0x%X)\n", GetLastError());
		return 0;

	}

	schService = OpenServiceA(schSCManager, "EventLog", SERVICE_QUERY_STATUS);

	if (schService == NULL) {

		printf("[!] Service handle unavailable (0x%X)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return 0;

	}

	if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssProcess), sizeof(ssProcess), &dwBytesNeeded)) {

		printf("[!] Service status query failed (0x%X)\n", GetLastError());
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return 0;

	}

	return ssProcess.dwProcessId;
}

