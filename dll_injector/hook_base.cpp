#include "hook_base.hpp"
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
#include "config.hpp"

using namespace std;


void* trampolineExecutableCode__global = nullptr;

int ProxyFunctions::proxy__libc_open (const char *file, int flags)
{
	string fakeFile = "/tmp/fileWithFakeLines.txt";
	int resOfOrigin = ((int(*)(const char*, int ))trampolineExecutableCode__global)(fakeFile.c_str(), flags);
	return resOfOrigin;
}


HookSetBase::HookSetBase(void* injection_addr, Proxies proxy_choosen, LoggerFunctionPtr fpLogger):
	_injection_addr(reinterpret_cast<uint32_t>(injection_addr)),
	_proxy_function(_get_proxy_by_flag(proxy_choosen)),
	_logger(fpLogger),
	_memoryImageBuffer(Consts::MAX_POSSIBLE_TRAMPOLINE_SIZE),
	_original_code_and_jmp_to_target_plus_N(_alloc_for_trampoline_executable_space())
{
	_loadTraceeMemoryImage(_memoryImageBuffer, (void*)_injection_addr);
	_logger("Indicators has been initiated.");
}

HookSetBase::~HookSetBase()
{
	_logger("Hook writer d'tor");
}

bool HookSetBase::inject_to_libc_open() 
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
	
	
	
void HookSetBase::_writeTheHook()
{
	_logger("writing the jump to the proxy function.");
	char jumpToProxyFunction[Consts::JUMP_SIZE] = {static_cast<char>(0xE9), 0x00, 0x00, 0x00, 0x00};
	static const uint32_t offset_of_address = 1; 
	*reinterpret_cast<uint32_t *>(&jumpToProxyFunction[offset_of_address]) = static_cast<uint32_t>(_proxy_function) - (static_cast<uint32_t>(_injection_addr) + Consts::JUMP_SIZE);

	_setTargetAddressToWrite(Consts::JUMP_SIZE);
	memcpy((void*)_injection_addr, (void*)jumpToProxyFunction, Consts::JUMP_SIZE);
	_setTargetAddressToRead(Consts::JUMP_SIZE);
			
}

uint8_t* HookSetBase::_alloc_for_trampoline_executable_space()
{
	return reinterpret_cast<uint8_t*>(mmap(NULL,
		Consts::MAX_POSSIBLE_TRAMPOLINE_SIZE,
		PROT_EXEC | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE,
		-1,
		0));
}

uint32_t HookSetBase::_get_proxy_by_flag(Proxies proxy_choosen) const
{
	switch(proxy_choosen)
	{
		case Proxies::GLIBC_OPEN:
			return (uint32_t)ProxyFunctions::proxy__libc_open;
			break;
		default:
			return (uint32_t)nullptr;
			break;
	}
}

int HookSetBase::_getHowManyBytesToSave()const
{

	const void* functionAddress = reinterpret_cast<void*>(_injection_addr);
	unsigned int trampolineLength = 0;
	hde32s disam;

	if(!functionAddress)
	{
		_logger("not valid target address. injection is canceled! " + (trampolineLength));
	 	return 0;
	}
	
	
	while(trampolineLength < Consts::JUMP_SIZE)
	{
		_logger("trampoline Length is " + to_string(trampolineLength) + " bytes");
	 	void* instructionPointer = (void*)((unsigned int)_memoryImageBuffer.data() + trampolineLength);
	 	trampolineLength += hde32_disasm(instructionPointer, &disam);
	}
	return trampolineLength;
		
}

void HookSetBase::_buildTrampoline(int _NBytesToBackup)
{
	if(_original_code_and_jmp_to_target_plus_N == nullptr)
	{
		_logger("does not have enough space to build trampolint. build is canceled.");
		return;
	}
	
	_logger("copying first " + to_string(_NBytesToBackup)+ "  bytes in tracee memory.");
	memcpy(_original_code_and_jmp_to_target_plus_N, this->_memoryImageBuffer.data(), _NBytesToBackup);
	
	unsigned long addressInTargetAfterJumpToProxy = ((unsigned long)_injection_addr + _NBytesToBackup); // see "position 1" in the README.md in this directory.
	unsigned long addressInThisTrampolineExecCodeAfterJumpInstruction = ((unsigned long)_original_code_and_jmp_to_target_plus_N + _NBytesToBackup + Consts::JUMP_SIZE); //see "position 2" in the README.md .
	char jump[Consts::JUMP_SIZE] = {(char)0xE9, 0x00, 0x00, 0x00, 0x00};
	*(unsigned long*)(jump+1) =  addressInTargetAfterJumpToProxy - addressInThisTrampolineExecCodeAfterJumpInstruction;
	memcpy(
		(void*)((unsigned long)_original_code_and_jmp_to_target_plus_N + _NBytesToBackup),
		jump, 
		Consts::JUMP_SIZE						
	);
	_logger("trampoline has built.");
	_logger("assigning the global trampoline pointer to the one that created in this object.");
	trampolineExecutableCode__global = _original_code_and_jmp_to_target_plus_N;
		
}


bool HookSetBase::_loadTraceeMemoryImage(std::vector<uint8_t>& imageBuffer, void* startAddr)const
{
	_setTargetAddressToRead(Consts::MAX_POSSIBLE_TRAMPOLINE_SIZE);
	memcpy(imageBuffer.data(), (void *)_injection_addr, imageBuffer.size());
	_logger("memory image at the address of the target saved in buffer.");
	return true;
}

void* HookSetBase::_roundDownToPageBoundary(void* addr)const
{
	static uint32_t pagesize = sysconf(_SC_PAGE_SIZE);
	return (void*)((uint32_t)addr & ~(pagesize - 1));

}

void HookSetBase::_setTargetAddressToRead(size_t length)const
{
	mprotect(_roundDownToPageBoundary((void*)_injection_addr),
		       	Consts::MAX_POSSIBLE_TRAMPOLINE_SIZE,
		       	PROT_READ | PROT_EXEC);
}

void HookSetBase::_setTargetAddressToWrite(size_t length)const
{
	mprotect(_roundDownToPageBoundary((void*)_injection_addr),
		       	Consts::MAX_POSSIBLE_TRAMPOLINE_SIZE,
		       	PROT_WRITE | PROT_EXEC);
}















