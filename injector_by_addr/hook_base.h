

#include <iostream>
#include <stdint.h>
#include <string>
#include <exception>
#include <stdlib.h>
#include <sstream>
#include <iomanip>
#include <sys/ptrace.h>
#include<unistd.h>
#include<sys/wait.h>
#include <cstring>
#include <sys/mman.h>
#include <sys/user.h>

//open source
#include "hde32.h"

using namespace std;
using LoggerFunctionPtr = void (*)(std::string);

constexpr size_t MAX_POSSIBLE_TRAMPOLINE_SIZE = 25;


class HookSetBase
{

public:
	HookSetBase(uint32_t injection_addr, uint32_t proxyFunction, LoggerFunctionPtr _fpLogger)
	:_JUMP_SIZE(5),
	_injection_addr(injection_addr), //TODO: need a static cast here,
	_proxy_function(proxyFunction),
	_logger(_fpLogger),
	_original_code_and_jmp_to_target_plus_N(_alloc_for_trampoline_executable_space()),
	_memoryImageBuffer(new char[MAX_POSSIBLE_TRAMPOLINE_SIZE])
	{
		_loadTraceeMemoryImage(_memoryImageBuffer, (void*)_injection_addr, MAX_POSSIBLE_TRAMPOLINE_SIZE);
		_logger("Indicators has been initiated.");
	}
	
	~HookSetBase()
	{
		delete _memoryImageBuffer;
		_logger("Been there done that.");
	}
	
	bool inject_to_libc_open() 
	{
		_logger("cheking trampoline length");
		unsigned int _NBytesToBackup = _getHowManyBytesToSave();
		if(!_NBytesToBackup)
		{
			return false;
		}
		_logger("trampoline length is " + to_string(_NBytesToBackup));
		_buildTrampoline(_NBytesToBackup);
		_writeTheHook();
		
		return true;
	}
	
	
	
private:
	const size_t _JUMP_SIZE;
	const uint32_t _injection_addr=0;
	const uint32_t _proxy_function=0;
	LoggerFunctionPtr _logger=nullptr;
	char* _original_code_and_jmp_to_target_plus_N=nullptr;//AKA trampoline
	char* const _memoryImageBuffer=nullptr;
	
	void _writeTheHook()
	{
		_logger("writing the jump to the proxy function.");
		char jumpToProxyFunction[_JUMP_SIZE] = {(char)0xE9, 0x00, 0x00, 0x00, 0x00};
		*(unsigned long *)(jumpToProxyFunction+1) = (unsigned long)_proxy_function - ((unsigned long)_injection_addr + _JUMP_SIZE);

		_setTargetAddressToWrite(_JUMP_SIZE);

		//uint32_t originalTextCodeInPlus_4_Bytes = ((uint32_t*)_memoryImageBuffer)[1];
		memcpy(_injection_addr, jumpToProxyFunction, _JUMP_SIZE);//put last byte left from jump into next block of code to inject. reserving the rest of the text(that shoud by complete instructions)
		//uint32_t lowerPartOfJump = *((uint32_t*)jumpToProxyFunction);
		//uint32_t upperPrtOfJump = originalTextCodeInPlus_4_Bytes;
		
		//(void)lowerPartOfJump;
		//(void)upperPrtOfJump;
		_setTargetAddressToRead(_JUMP_SIZE);
				
	}
	
	char* _alloc_for_trampoline_executable_space()const
	{
		return (char*)mmap(NULL,
			MAX_POSSIBLE_TRAMPOLINE_SIZE,
			PROT_EXEC | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, // may be upgraded to MAP_PRIVATE later
			-1,
			0);
	}
	

	int _getHowManyBytesToSave()const
	{

		const void* functionAddress = reinterpret_cast<void*>(_injection_addr);
		unsigned int trampolineLength = 0;
		hde32s disam;

		if(!functionAddress)
		{
			_logger("not valid target address. injection is canceled! " + (trampolineLength));
		 	return 0;
		}
		
		
		while(trampolineLength < _JUMP_SIZE)
		{
			_logger("trampoline Length is " + to_string(trampolineLength) + " bytes");
		 	void* instructionPointer = (void*)((unsigned int)_memoryImageBuffer + trampolineLength);
		 	trampolineLength += hde32_disasm(instructionPointer, &disam);
		}
		return trampolineLength;
			
	}
	
	void _buildTrampoline(int _NBytesToBackup)
	{
		if(_original_code_and_jmp_to_target_plus_N == nullptr)
		{
			_logger("does not have enough space to build trampolint. build is canceled.");
			return;
		}
		
		_logger("copying first " + to_string(_NBytesToBackup)+ "  bytes in tracee memory.");
		memcpy(_original_code_and_jmp_to_target_plus_N, this->_memoryImageBuffer, _NBytesToBackup);
		
		unsigned long addressInTargetAfterJumpToProxy = ((unsigned long)_injection_addr + _NBytesToBackup); // see "position 1" in the README.md in this directory.
		unsigned long addressInThisTrampolineExecCodeAfterJumpInstruction = ((unsigned long)_original_code_and_jmp_to_target_plus_N + _NBytesToBackup + _JUMP_SIZE); //see "position 2" in the README.md .
		char jump[5] = {(char)0xE9, 0x00, 0x00, 0x00, 0x00};
		*(unsigned long*)(jump+1) =  addressInTargetAfterJumpToProxy - addressInThisTrampolineExecCodeAfterJumpInstruction; //TODO: verify that can subtract local address with tracee's
		memcpy(
			(void*)((unsigned long)_original_code_and_jmp_to_target_plus_N + _NBytesToBackup),
			jump, 
			_JUMP_SIZE						
		);
		_logger("trampoline has built.");
			
	}
	
	
	bool _loadTraceeMemoryImage(char* imageBuffer, void* startAddr, size_t length)const
	{
		if(!imageBuffer)
		{
			_logger("Could not copy memoty image of target process to buffer!");
			return false;	
		}

		_setTargetAddressToRead(MAX_POSSIBLE_TRAMPOLINE_SIZE);
		memcpy(imageBuffer, (void *)_injection_addr, MAX_POSSIBLE_TRAMPOLINE_SIZE);
		_logger("memory image at the address of the target saved in buffer.");
		return true;
	}

	void* _roundDownToPageBoundary(void* addr)const
	{
		static uint32_t pagesize = sysconf(_SC_PAGE_SIZE);
		return (void*)((uint32_t)addr & ~(pagesize - 1));

	}

	void _setTargetAddressToRead(size_t length)const
	{
		mprotect(_roundDownToPageBoundary((void*)_injection_addr),
			       	MAX_POSSIBLE_TRAMPOLINE_SIZE,
			       	PROT_READ | PROT_EXEC);
	}
	
	void _setTargetAddressToWrite(size_t length)const
	{
		mprotect(_roundDownToPageBoundary((void*)_injection_addr),
			       	MAX_POSSIBLE_TRAMPOLINE_SIZE,
			       	PROT_WRITE | PROT_EXEC);
	}

};















