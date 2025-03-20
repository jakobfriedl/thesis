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
#define NtOpenProcess_HASH 0x87BF792803716576
#define NtOpenThread_HASH 0x803C1AF1BB28AB2F
#define NtAllocateVirtualMemory_HASH 0xB93E3F9D68F0E5EA
#define NtWriteVirtualMemory_HASH 0x90409184AAAC9EF0
#define NtProtectVirtualMemory_HASH 0x079775FC2EFDA9A6
#define NtGetContextThread_HASH 0x4F89397AA6C5A222
#define NtSetContextThread_HASH 0xDF24065F394368AE
#define NtResumeThread_HASH 0x818FCBEA4D9D860E
#define NtSuspendThread_HASH 0xD5E6F168966A21FF
#define NtWaitForSingleObject_HASH 0xE1D9A22DF845A95A
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
    NT_SYSCALL NtOpenProcess;
    NT_SYSCALL NtOpenThread;
    NT_SYSCALL NtAllocateVirtualMemory;
    NT_SYSCALL NtProtectVirtualMemory;
    NT_SYSCALL NtWriteVirtualMemory;
    NT_SYSCALL NtGetContextThread;
    NT_SYSCALL NtSetContextThread;
    NT_SYSCALL NtSuspendThread;
    NT_SYSCALL NtResumeThread;
    NT_SYSCALL NtWaitForSingleObject;
    NT_SYSCALL NtClose;
} NTAPI_FUNC, * PNTAPI_FUNC;

// Function prototypes for indirect syscalls
extern VOID PrepareSyscall(WORD wSystemCall);
extern RunSyscall();

#define SET_SYSCALL(NtSys)(PrepareSyscall((DWORD)NtSys.dwSSN,(PVOID)NtSys.pSyscallInstAddress))

DWORD64 djb2(PBYTE str);
VOID PrintHashes();
BOOL InitializeIndirectSyscalls(PNTAPI_FUNC Nt);