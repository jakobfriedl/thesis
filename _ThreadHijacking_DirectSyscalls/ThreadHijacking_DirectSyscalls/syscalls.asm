; Hell's Gate
; Dynamic system call invocation 
; 
; by smelly__vx (@RtlMateusz) and am0nsec (@am0nsec)

.data
	wSystemCall DWORD 000h

.code 
	PrepareSyscall PROC
		nop
		mov wSystemCall, 000h
		nop
		mov wSystemCall, ecx
		nop
		ret
	PrepareSyscall ENDP

	RunSyscall PROC
		nop
		mov rax, rcx
		nop
		mov r10, rax
		nop
		mov eax, wSystemCall
		nop
		syscall
		ret
	RunSyscall ENDP
end