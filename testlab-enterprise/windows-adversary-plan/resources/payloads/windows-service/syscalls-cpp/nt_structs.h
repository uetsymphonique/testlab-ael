#ifndef NT_STRUCTS_H
#define NT_STRUCTS_H

#include <windows.h>

// NTSTATUS type
typedef LONG NTSTATUS;

// Unicode string structure
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// Object attributes structure
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// IO Status block
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

// NTSTATUS codes
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_OBJECT_NAME_NOT_FOUND     ((NTSTATUS)0xC0000034L)
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)

// Object attributes flags
#define OBJ_CASE_INSENSITIVE             0x00000040

// Note: KEY_*, REG_*, and DELETE constants are already defined in winnt.h
// and will be automatically included via windows.h

// Service constants
#define SERVICE_WIN32_OWN_PROCESS        0x00000010
#define SERVICE_AUTO_START               0x00000002
#define SERVICE_DEMAND_START             0x00000003
#define SERVICE_ERROR_NORMAL             0x00000001

// Registry paths
#define SERVICES_KEY_PATH L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services"

#endif // NT_STRUCTS_H
