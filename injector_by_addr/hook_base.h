

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


void logerToStdOut(std::string logMsg)
{
	cout << "[>> log message << ] " << logMsg <<endl;
}

namespace proxies
{
	int proxy__libc_open (const char *file, int oflag)
	{
		printf("inside the proxy function!!! \n");
		//int resOfOrigin =(int(*)(const char*, int ))exutetefirstN(x);
		return -1;
	}
}



class MyArgs
{
public:
	MyArgs(char* _pid, char* _injection_addr, string sharedObject)
	{
		pid = strtoul(_pid, nullptr, 10);
		std::istringstream converter(_injection_addr);
		converter >> std::hex >> injection_addr;
		_sharedObject = sharedObject;
			
	}
	unsigned long pid;
	uint32_t injection_addr;
	string sharedObject;
	
};


class HookSetBase
{

public:
	HookSetBase(void* injection_addr,void* proxyFunction, LoggerFunctionPtr _fpLogger)
	:_JUMP_SIZE(5),
	_traceeMemoryImageBuffer(new char[MAX_POSSIBLE_TRAMPOLINE_SIZE]),
	_targetPid(targetPid),
	_injection_addr(injection_addr),
	_logger(_fpLogger),
	_original_code_and_jmp_to_target_plus_N(_alloc_for_trampoline_executable_space())
	{
		_loadTraceeMemoryImage(_traceeMemoryImageBuffer, (void*)_injection_addr, MAX_POSSIBLE_TRAMPOLINE_SIZE);
		_logger("Indicators has been initiated.");
	}
	
	~HookSetBase()
	{
		delete _traceeMemoryImageBuffer;
		_logger("Been there done that.");
	}
	
	// deprecated!!!
	/*bool inject_to_libc_open() 
	{
		ptrace(PTRACE_ATTACH, _targetPid, NULL, NULL);
		wait(NULL);
		_logger("cheking trampoline length"); 	
		unsigned int _NBytesToBackup = _getHowManyBytesToSave();
		if(!_NBytesToBackup)
		{
			return false;
		}
		
		_logger("trampoline length is " + to_string(_NBytesToBackup));
		_buildTrampoline(_NBytesToBackup);
		_writeTheHook();
		
		ptrace(PTRACE_DETACH, _targetPid, NULL, NULL);
		return true;
	}
	*/
	
	void injectSharedObject(string pathOfShared)
	{
		_logger("injectSharedObject - is not supported yet!");
	}
	
		
	
	
private:
	const size_t _JUMP_SIZE;
	const unsigned long _targetPid;
	const uint32_t _injection_addr;
	LoggerFunctionPtr _logger=nullptr;
	char* _original_code_and_jmp_to_target_plus_N=nullptr;//AKA trampoline
	char* const _traceeMemoryImageBuffer=nullptr;
	
	void _writeTheHook()
	{
		_logger("writing the jump to the proxy function.");
		char jumpToProxyFunction[5] = {(char)0xE9, 0x00, 0x00, 0x00, 0x00};
		*(unsigned long *)(jumpToProxyFunction+1) = (unsigned long)proxies::proxy__libc_open - ((unsigned long)_injection_addr + 5); //TODO: verify that can subtract local address with tracee's
		
		uint32_t originalTextCodeInPlus_4_Bytes = ((uint32_t*)_traceeMemoryImageBuffer)[1];
		memcpy(&originalTextCodeInPlus_4_Bytes, jumpToProxyFunction+4, 1);//put last byte left from jump into next block of code to inject. reserving the rest of the text(that shoud by complete instructions)
		uint32_t lowerPartOfJump = *((uint32_t*)jumpToProxyFunction);
		uint32_t upperPrtOfJump = originalTextCodeInPlus_4_Bytes;
		
		ptrace(PTRACE_POKETEXT,
				_targetPid,
				_injection_addr,
				(void*)(&lowerPartOfJump));
		ptrace(PTRACE_POKETEXT,
				_targetPid,
				_injection_addr + sizeof(lowerPartOfJump),
				(void*)(&upperPrtOfJump));
				
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
			_logger("not valaid target address. injection is canceled! " + (trampolineLength));
		 	return 0;
		}
		
		
		while(trampolineLength < _JUMP_SIZE)
		{
			_logger("trampoline Length is " + to_string(trampolineLength) + " bytes");
		 	void* instructionPointer = (void*)((unsigned int)_traceeMemoryImageBuffer + trampolineLength);
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
		memcpy(_original_code_and_jmp_to_target_plus_N, this->_traceeMemoryImageBuffer, _NBytesToBackup);
		unsigned long addressInTargetAfterJumpToProxy = ((unsigned long)_injection_addr + _NBytesToBackup); // see "position 1" in the README.md in this directory.
		unsigned long addressInTrampolineExecCodeAfterJumpInstruction = ((unsigned long)_original_code_and_jmp_to_target_plus_N + _NBytesToBackup + 5); //see "position 2" in the README.md .
		char jump[5] = {(char)0xE9, 0x00, 0x00, 0x00, 0x00};
		*(unsigned long*)(jump+1) = addressInTrampolineExecCodeAfterJumpInstruction - addressInTargetAfterJumpToProxy; //TODO: verify that can subtract local address with tracee's
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
		
		uint32_t currentImageSize = 0;
		uint32_t offsetFromStart =0;
		
		while(currentImageSize < length)
		{
			long inst = ptrace(
				PTRACE_PEEKTEXT,
				_targetPid,
                (void*)((uint32_t)startAddr + offsetFromStart),
                NULL);
			memcpy(
           		imageBuffer + offsetFromStart,
           		&inst,
           		sizeof(inst));
           
           offsetFromStart += sizeof(inst);
           currentImageSize += sizeof(inst);
		}
		
		return true;
	}
	

};


MyArgs validateArgs(int argc, char* argv[])
{
	if(argc < 4)
	{
		cout << "Wrong Args!\n	Usage: [PID] [TARGET_ADDRESS] [SHARED_OBJ]\n";
		throw exception();
	}
	
	return MyArgs(argv[1], argv[2], argv[3]);	
}

/*int main(int argc, char* argv[])
{
	cout << "Run Me With sudo (!) " << endl;
	MyArgs args = validateArgs(argc, argv);
	Injector32 nurse(args.pid, args.injection_addr, logerToStdOut);
	nurse.injectSharedObject(args.sharedObject);

}*/















