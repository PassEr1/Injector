SECTION .data
        global _start
_start:	
	mov eax, 0xffffffff
	push 2 ;RTLD_NOW
	call bypass_dll_name
dll_name: db 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
bypass_dll_name:
	
        call eax
	add esp,8
	ret ; exit from shellcode




