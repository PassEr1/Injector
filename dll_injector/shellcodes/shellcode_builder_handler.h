#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sys/mman.h>
using namespace std;
//31c0 31db 31c9 31d2 6a02 6868 9004 08e8 976f fbf7 0000 0000 0000 0000 0000
//                                                                V call 0xffffffff                                           V name_of_dll
unsigned char shellcode_i386[] = "\xb8\xff\xff\xff\xff\x6a\x02\xe8\x1e\x00\x00\x00\x34\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xd0\x83\xc4\x08\xc3";
static uint32_t i386_posOfFunctionAddress = 1;
static uint32_t i386_posOfDllName = 12;
#define SHELL_CODE_BUFFER_LEN sizeof(shellcode_i386)

namespace completeShellCode
{
	char* _alloc_for_executable_space()
	{
		return (char*)mmap(NULL,
			SHELL_CODE_BUFFER_LEN,
			PROT_EXEC | PROT_WRITE | PROT_READ,
			MAP_ANONYMOUS | MAP_PRIVATE,
			-1,
			0);
	}

	char* getShellCodeCall_dlopen_i386(void* addressOfFunction, string nameOfDll_upTo40Bytes)
	{
		*((uint32_t*)((uint32_t)shellcode_i386 + i386_posOfFunctionAddress)) = (uint32_t)addressOfFunction;
		memcpy((void*)((uint32_t)shellcode_i386 + i386_posOfDllName), (void*)nameOfDll_upTo40Bytes.c_str(), nameOfDll_upTo40Bytes.size());
		char* finalExecBufferToReturn = completeShellCode::_alloc_for_executable_space();
		memcpy((void*)finalExecBufferToReturn, (void*)shellcode_i386, SHELL_CODE_BUFFER_LEN);
		return (char*)finalExecBufferToReturn;
	}
}

