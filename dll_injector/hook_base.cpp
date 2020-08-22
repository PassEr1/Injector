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
#include <exception>

//open source
#include "hde32.h"
#include "config.hpp"
#include "memory_protection_context.hpp"

using namespace std;


void* trampolineExecutableCode__global = nullptr;

int ProxyFunctions::proxy__libc_open (const char *file, int flags)
{
	string fakeFile = "/tmp/fileWithFakeLines.txt";
	using GlibcOpenFunctionPtr = int(*)(const char*, int );
	int resOfOrigin = ((GlibcOpenFunctionPtr)trampolineExecutableCode__global)(fakeFile.c_str(), flags);
	
	return resOfOrigin;
}


HookSetBase::HookSetBase(void* injection_addr, Proxies proxy_choosen, LoggerFunctionPtr fpLogger):
	_injection_addr(reinterpret_cast<uint32_t>(injection_addr)),
	_proxy_function(_getProxyByFlag(proxy_choosen)),
	_logger(fpLogger),
	_memoryImageBuffer(Consts::MAX_POSSIBLE_TRAMPOLINE_SIZE),
	_original_code_and_jmp_to_proxy(Consts::MAX_POSSIBLE_TRAMPOLINE_SIZE, PROT_EXEC | PROT_WRITE)
{
	_loadTraceeMemoryImage(_memoryImageBuffer, (void*)_injection_addr);
	_logger("Indicators has been initiated.");
}

HookSetBase::~HookSetBase()
{
	_logger("Hook writer d'tor");
	
}

void HookSetBase::hook() 
{
	_logger("cheking trampoline length");
	unsigned int bytesToBackupCount = _getHowManyBytesToSave();
	
	if(!bytesToBackupCount)
	{
		_logger("bytes to backup invalid value");
		throw std::exception();
	}
	
	_logger("trampoline length is " + to_string(bytesToBackupCount));
	_buildTrampoline(bytesToBackupCount);
	_writeTheHook();
}
	
	
	
void HookSetBase::_writeTheHook()
{
	_logger("writing the jump to the proxy function.");
	char jumpToProxyFunction[Consts::JUMP_SIZE] = {static_cast<char>(0xE9), 0x00, 0x00, 0x00, 0x00};
	
	static const uint32_t offset_of_address = 1; 
	*reinterpret_cast<uint32_t *>(&jumpToProxyFunction[offset_of_address]) = static_cast<uint32_t>(_proxy_function) - (static_cast<uint32_t>(_injection_addr) + Consts::JUMP_SIZE);

	MemoryProtectionContext memory_write_context(reinterpret_cast<void*>(_injection_addr), Consts::JUMP_SIZE);
	memcpy((void*)_injection_addr, (void*)jumpToProxyFunction, Consts::JUMP_SIZE);
			
}

uint32_t HookSetBase::_getProxyByFlag(Proxies proxy_choosen)
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

void HookSetBase::_buildTrampoline(int bytesToBackupCount)
{	
	_logger("copying first " + to_string(bytesToBackupCount)+ "  bytes in tracee memory.");
	memcpy(_original_code_and_jmp_to_proxy.get_data(), this->_memoryImageBuffer.data(), bytesToBackupCount);
	
	unsigned long addressInTargetAfterJumpToProxy = ((unsigned long)_injection_addr + bytesToBackupCount); // see "position 1" in the README.md in this directory.
	unsigned long addressInThisTrampolineExecCodeAfterJumpInstruction = ((unsigned long)_original_code_and_jmp_to_proxy.get_data() + bytesToBackupCount + Consts::JUMP_SIZE); //see "position 2" in the README.md .
	char jump[Consts::JUMP_SIZE] = {(char)0xE9, 0x00, 0x00, 0x00, 0x00};
	*(unsigned long*)(jump+1) =  addressInTargetAfterJumpToProxy - addressInThisTrampolineExecCodeAfterJumpInstruction;
	memcpy(
		(void*)((unsigned long)_original_code_and_jmp_to_proxy.get_data() + bytesToBackupCount),
		jump, 
		Consts::JUMP_SIZE						
	);
	_logger("trampoline has built.");
	_logger("assigning the global trampoline pointer to the one that created in this object.");
	trampolineExecutableCode__global = _original_code_and_jmp_to_proxy.get_data();
		
}


bool HookSetBase::_loadTraceeMemoryImage(std::vector<uint8_t>& imageBuffer, void* startAddr)const
{
	MemoryProtectionContext::change_memory_mode(reinterpret_cast<void*>(_injection_addr), Consts::MAX_POSSIBLE_TRAMPOLINE_SIZE, PROT_READ | PROT_EXEC);
	memcpy(imageBuffer.data(), (void *)_injection_addr, imageBuffer.size());
	_logger("memory image at the address of the target saved in buffer.");
	return true;
}















