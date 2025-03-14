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
#define NtCreateSection_HASH 0x6125236A1599856E
#define NtMapViewOfSection_HASH 0x00B5B0DE2BD6A148
#define NtUnmapViewOfSection_HASH 0x478453B66E090C0B
#define NtCreateThreadEx_HASH 0x85C990B7BDE4198E
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
    NT_SYSCALL NtCreateSection;
    NT_SYSCALL NtMapViewOfSection;
    NT_SYSCALL NtUnmapViewOfSection;
    NT_SYSCALL NtWriteVirtualMemory;
    NT_SYSCALL NtCreateThreadEx;
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