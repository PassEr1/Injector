SECTION .data
        global _start
_start:
        xor eax, eax
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx
	
	mov eax, 0xffffffff
	push 2 ;RTLD_NOW
	push dll_name ;REALTIVE ADDRESS OF dll name
        call eax
	ret ; exit from shellcode
dll_name: db 0x99, 0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99, 0x99, 0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99, 0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99



