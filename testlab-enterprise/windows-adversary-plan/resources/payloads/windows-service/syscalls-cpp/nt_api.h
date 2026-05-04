#ifndef NT_API_H
#define NT_API_H

#include "nt_structs.h"

// NT API function pointers
typedef NTSTATUS (NTAPI *pNtCreateKey)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition
);

typedef NTSTATUS (NTAPI *pNtOpenKey)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI *pNtSetValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize
);

typedef NTSTATUS (NTAPI *pNtQueryValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    int KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
);

typedef NTSTATUS (NTAPI *pNtDeleteKey)(
    HANDLE KeyHandle
);

typedef NTSTATUS (NTAPI *pNtDeleteValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName
);

typedef NTSTATUS (NTAPI *pNtClose)(
    HANDLE Handle
);

typedef VOID (NTAPI *pRtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

// Global function pointers
extern pNtCreateKey NtCreateKey;
extern pNtOpenKey NtOpenKey;
extern pNtSetValueKey NtSetValueKey;
extern pNtQueryValueKey NtQueryValueKey;
extern pNtDeleteKey NtDeleteKey;
extern pNtDeleteValueKey NtDeleteValueKey;
extern pNtClose NtClose;
extern pRtlInitUnicodeString RtlInitUnicodeString;

// Initialization
BOOL InitNtFunctions();

// Helper functions
VOID InitUnicodeString(PUNICODE_STRING dest, PCWSTR source);
VOID FreeUnicodeString(PUNICODE_STRING str);
VOID InitObjectAttributes(
    POBJECT_ATTRIBUTES oa,
    PUNICODE_STRING objectName,
    ULONG attributes,
    HANDLE rootDirectory
);

#endif // NT_API_H
