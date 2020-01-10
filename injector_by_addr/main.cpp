

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


//open source code
#include "hde32.h"

using namespace std;
using LoggerFunctionPtr = void (*)(std::string);


void logerToStdOut(std::string logMsg)
{
	cout <<"[>> log message << ] " << logMsg <<endl;
}

namespace proxies
{
	int proxy__libc_open (const char *file, int oflag)
	{
		//Auto a =(int(*)(int &))exutetefirstN(x);
		return -1;
	}
}



class MyArgs
{
public:
	MyArgs(char* _pid, char* _injection_addr)
	{
		pid = strtoul(_pid, nullptr, 10);
		std::istringstream converter(_injection_addr);
		converter >> std::hex >> injection_addr;
			
	}
	unsigned long pid;
	uint32_t injection_addr;
};

class Injector
{

public:
	Injector(unsigned long targetPid, uint32_t injection_addr,LoggerFunctionPtr _fpLogger)
	:_JUMP_SIZE(5),
	_targetPid(targetPid),
	_injection_addr(injection_addr),
	_logger(_fpLogger),
	_original_code_and_jmp_to_target_plus_N(_alloc_for_trampoline_executable_space())
	{
		_logger("Indicators has been initiated.");
	}
	
	~Injector()
	{
		_logger("Been there done that.");
	}
	
	bool inject_to_libc_open()
	{
		ptrace(PTRACE_ATTACH, _targetPid, NULL, NULL);
		wait(NULL);
		_logger("cheking trampoline length"); 	
		unsigned int _NBytesToBackup = this->_getHowManyBytesToSave();
		_logger("trampoline length is " + to_string(_NBytesToBackup));
		
		_buildTrampoline(_NBytesToBackup);
		
		ptrace(PTRACE_DETACH, _targetPid, NULL, NULL);
		return true;
	}
	
		
	
	
private:
	const size_t _JUMP_SIZE;
	const unsigned long _targetPid;
	const uint32_t _injection_addr;
	LoggerFunctionPtr _logger=nullptr;
	char* _original_code_and_jmp_to_target_plus_N=nullptr;//AKA trampoline
	
	char* _alloc_for_trampoline_executable_space()const
	{
		return (char*)mmap(NULL,
			_JUMP_SIZE,
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
		 
		//disassemble length of each instruction, until we have 5 or more bytes worth
		while(trampolineLength < 5)
		{
			_logger("trampoline Length is " + to_string(trampolineLength) + " bytes");
		 	void* instructionPointer = (void*)((unsigned int)functionAddress + trampolineLength);
			printf("current instruction being scanned is: 0x%p\n", instructionPointer);
		 	trampolineLength += hde32_disasm(instructionPointer, &disam);
		}
		_logger("after while trampoline length is " + to_string(trampolineLength) + " bytes");
		return trampolineLength;
			
	}
	
	void _buildTrampoline(int _NBytesToBackup)
	{
		unsigned long addressInTargetAfterJumpToProxy = ((unsigned long)_injection_addr + _NBytesToBackup);
		unsigned long addressInTrampolineExecCodeAfterJumpInstruction = ((unsigned long)_original_code_and_jmp_to_target_plus_N + _NBytesToBackup + 5);
		char jump[5] = {(char)0xE9, 0x00, 0x00, 0x00, 0x00};
		*(unsigned long*)(jump+1) = addressInTrampolineExecCodeAfterJumpInstruction - addressInTargetAfterJumpToProxy;
		memcpy(
			(void*)((unsigned long)_original_code_and_jmp_to_target_plus_N + _NBytesToBackup),
			jump,
			5						
		);
			
	}
	

};


MyArgs validateArgs(int argc, char* argv[])
{
	if(argc < 3)
	{
		cout << "Wrong Args!\n	Usage: [PID] [TARGET_ADDRESS] \n";
		throw exception();
	}
	
	return MyArgs(argv[1], argv[2]);	
}

int main(int argc, char* argv[])
{
	cout << "Run Me With sudo (!) " << endl;
	MyArgs args = validateArgs(argc, argv);
	Injector nurse(args.pid, args.injection_addr, logerToStdOut);
	nurse.inject_to_libc_open();

}








