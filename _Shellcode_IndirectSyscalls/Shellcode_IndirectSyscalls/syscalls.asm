.data
	wSystemCall         DWORD	0h	
	qSyscallInsAdress   QWORD	0h	


.code

    PrepareSyscall proc	
		xor eax, eax                          ; eax = 0
		nop
		mov wSystemCall, eax                  ; wSystemCall = 0
		nop
		mov qSyscallInsAdress, rax            ; qSyscallInsAdress = 0
		nop
		mov eax, ecx                          ; eax = ssn
		nop
		mov wSystemCall, eax                  ; wSystemCall = eax = ssn
		nop
		mov r8, rdx                           ; r8 = AddressOfASyscallInst
		nop
		mov qSyscallInsAdress, r8             ; qSyscallInsAdress = r8 = AddressOfASyscallInst
		nop
		ret 
    PrepareSyscall endp 
  
  
    RunSyscall proc
		xor r10, r10                          ; r10 = 0
		nop
		mov rax, rcx                          ; rax = rcx
		nop
		mov r10, rax                          ; r10 = rax = rcx
		nop
		mov eax, wSystemCall                  ; eax = ssn
		nop
		jmp Run                               ; execute 'Run'
		nop
		xor eax, eax      ; wont run
		nop
		xor rcx, rcx      ; wont run
		nop
		shl r10, 2        ; wont run
	Run:
		jmp qword ptr [qSyscallInsAdress]   ; jumping to the 'syscall' instruction
		nop
		xor r10, r10                        ; r10 = 0
		nop
		mov qSyscallInsAdress, r10          ; qSyscallInsAdress = 0
		nop
		ret
    RunSyscall endp

end