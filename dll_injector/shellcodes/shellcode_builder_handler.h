#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>

//31c0 31db 31c9 31d2 6a02 6868 9004 08e8 976f fbf7 0000 0000 0000 0000 0000
//                                                                                            V call 0xffffffff   V name_of_dll
unsigned char shellcode_i386[] = "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x6a\x02\x68\x68\x90\x04\x08\xe8\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
static unsigned int i386_posOfFunctionAddress = 15;
static unsigned int i386_posOfDllName = 20;

namespace completeShellCode
{
	char* getShellCodeCall_dlopen_i386(void* addressOfFunction, string nameOfDll_upTo30Bytes)
	{
		*((uint32_t)(shellcode_i386 + i386_posOfFunctionAddress)) = (uint32_t)addressOfFunction;
		memcpy((void*)shellcode_i386, (void*)nameOfDll_upTo30Bytes, nameOfDll_upTo30Bytes.size());
		return shellcode_i386;
	}
}


