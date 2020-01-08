

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
	:_targetPid(targetPid),
	_injection_addr(injection_addr),
	_logger(_fpLogger)
	{
		_logger("Indicators has been initiated.");
	}
	
	~Injector()
	{
		_logger("Been there done that.");
	}
	
	bool inject_to_libc_open()const
	{
		ptrace(PTRACE_ATTACH, _targetPid, NULL, NULL);
		wait(NULL);
		_logger("cheking trampoline length"); 	
		unsigned int _N_bytes_to_back_up = this->get_how_many_bytes_to_save();
		_logger("trampoline length is " + _N_bytes_to_back_up);
		
		ptrace(PTRACE_DETACH, _targetPid, NULL, NULL);
		return true;
	}
	
	
	
private:
	const unsigned long _targetPid;
	const uint32_t _injection_addr;
	LoggerFunctionPtr _logger=nullptr;
	char _original_code_and_jnp_to_pus_N[25];

	int get_how_many_bytes_to_save()const
	{
		const void* functionAddress = reinterpret_cast<void*>(_injection_addr);
		unsigned int trampolineLength = 0;
		hde32s disam;
		 
		if(!functionAddress)
		 return 0;
		 
		//disassemble length of each instruction, until we have 5 or more bytes worth
		while(trampolineLength < 5)
		{
			_logger("trampolineLength is " + (trampolineLength));
			_logger("instractionPointer is " + (trampolineLength));
		 	void* instructionPointer = (void*)((unsigned int)functionAddress + trampolineLength);
		 	trampolineLength += hde32_disasm(instructionPointer, &disam);
		}
		_logger("after while trampolineLength is " + (trampolineLength));
		return trampolineLength;
			
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
	nurse.inject_to_libc_open();
}








