#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sys/mman.h>
#include <vector>

using namespace std;

//here is:					   here is:
//|                                              |
//V call 0xffffffff                              V name_of_dll
uint8_t shellcode_i386[] = "\xb8\xff\xff\xff\xff\x6a\x02\xe8\x1e\x00\x00\x00\x34\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xd0\x83\xc4\x08\xc3";
static uint32_t i386_posOfFunctionAddress = 1;
static uint32_t i386_posOfDllName = 12 ;
#define SHELL_CODE_BUFFER_LEN sizeof(shellcode_i386)

namespace completeShellCode
{
	uint8_t* _alloc_for_executable_space()
	{
		return (uint8_t*)mmap(NULL,
			SHELL_CODE_BUFFER_LEN,
			PROT_EXEC | PROT_WRITE | PROT_READ,
			MAP_ANONYMOUS | MAP_PRIVATE,
			-1,
			0);
	}

	 uint8_t* getShellCodeCall_dlopen_i386(void* addressOfFunction, string nameOfDll_upTo40Bytes)
	{
		*((uint32_t*)((uint32_t)shellcode_i386 + i386_posOfFunctionAddress)) = (uint32_t)addressOfFunction;
		memcpy((void*)((uint32_t)shellcode_i386 + i386_posOfDllName), (void*)nameOfDll_upTo40Bytes.c_str(), nameOfDll_upTo40Bytes.size());
		uint8_t* finalExecBufferToReturn = completeShellCode::_alloc_for_executable_space();
		memcpy((void*)finalExecBufferToReturn, (void*)shellcode_i386, SHELL_CODE_BUFFER_LEN);
		return (uint8_t*)finalExecBufferToReturn;
	}
}


