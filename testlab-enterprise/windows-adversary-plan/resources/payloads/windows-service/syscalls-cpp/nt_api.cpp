#include "nt_api.h"
#include <stdio.h>

// Global function pointers
pNtCreateKey NtCreateKey = NULL;
pNtOpenKey NtOpenKey = NULL;
pNtSetValueKey NtSetValueKey = NULL;
pNtQueryValueKey NtQueryValueKey = NULL;
pNtDeleteKey NtDeleteKey = NULL;
pNtDeleteValueKey NtDeleteValueKey = NULL;
pNtClose NtClose = NULL;
pRtlInitUnicodeString RtlInitUnicodeString = NULL;

BOOL InitNtFunctions() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        wprintf(L"Failed to get ntdll.dll handle\n");
        return FALSE;
    }
    
    NtCreateKey = (pNtCreateKey)GetProcAddress(ntdll, "NtCreateKey");
    NtOpenKey = (pNtOpenKey)GetProcAddress(ntdll, "NtOpenKey");
    NtSetValueKey = (pNtSetValueKey)GetProcAddress(ntdll, "NtSetValueKey");
    NtQueryValueKey = (pNtQueryValueKey)GetProcAddress(ntdll, "NtQueryValueKey");
    NtDeleteKey = (pNtDeleteKey)GetProcAddress(ntdll, "NtDeleteKey");
    NtDeleteValueKey = (pNtDeleteValueKey)GetProcAddress(ntdll, "NtDeleteValueKey");
    NtClose = (pNtClose)GetProcAddress(ntdll, "NtClose");
    RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
    
    if (!NtCreateKey || !NtOpenKey || !NtSetValueKey || !NtClose || !RtlInitUnicodeString) {
        wprintf(L"Failed to load NT functions\n");
        return FALSE;
    }
    
    return TRUE;
}

VOID InitUnicodeString(PUNICODE_STRING dest, PCWSTR source) {
    if (!dest) return;
    
    if (source) {
        SIZE_T len = wcslen(source);
        dest->Length = (USHORT)(len * sizeof(WCHAR));
        dest->MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
        dest->Buffer = (PWSTR)source;
    } else {
        dest->Length = 0;
        dest->MaximumLength = 0;
        dest->Buffer = NULL;
    }
}

VOID FreeUnicodeString(PUNICODE_STRING str) {
    if (str && str->Buffer) {
        // Only free if we allocated (not using this for stack strings)
        str->Buffer = NULL;
        str->Length = 0;
        str->MaximumLength = 0;
    }
}

VOID InitObjectAttributes(
    POBJECT_ATTRIBUTES oa,
    PUNICODE_STRING objectName,
    ULONG attributes,
    HANDLE rootDirectory
) {
    if (!oa) return;
    
    oa->Length = sizeof(OBJECT_ATTRIBUTES);
    oa->RootDirectory = rootDirectory;
    oa->ObjectName = objectName;
    oa->Attributes = attributes;
    oa->SecurityDescriptor = NULL;
    oa->SecurityQualityOfService = NULL;
}
