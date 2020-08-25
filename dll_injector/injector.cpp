#include <iostream>
#include <stdint.h>
#include <string>
#include <exception>
#include <stdlib.h>
#include <sys/ptrace.h>
#include<sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include "shellcodes/shellcode_builder_handler.h"
//open source
#include "hde32.h"

#include "Args.hpp"

using namespace std;
using LoggerFunctionPtr = void (*)(const std::string&);

constexpr size_t MAX_POSSIBLE_TRAMPOLINE_SIZE = 25;


void logerToStdOut(const std::string& logMsg)
{
	cout << "[>> log message << ] " << logMsg <<endl;
}


class Injector32 final
{

public:
	Injector32(unsigned long targetPid, uint32_t injection_addr,LoggerFunctionPtr _fpLogger)
	:_JUMP_SIZE(5),
	_traceeMemoryImageBuffer(new char[MAX_POSSIBLE_TRAMPOLINE_SIZE]),
	_targetPid(targetPid),
	_injection_addr(injection_addr),
	_logger(_fpLogger)
	{
		_loadTraceeMemoryImage(_traceeMemoryImageBuffer, (void*)_injection_addr, MAX_POSSIBLE_TRAMPOLINE_SIZE);
		_logger("Indicators has been initiated.");
	}
	
	~Injector32()
	{
		delete _traceeMemoryImageBuffer;
		_logger("Been there done that.");
	}
	

	Injector32(const Injector32&) = delete;
	Injector32& operator=(const Injector32&) = delete;
	
	void injectSharedObject(string pathOfShared)
	{
		
		struct user_regs_struct regs;
		struct user_regs_struct old_regs;
		char* backup_memory_buffer[SHELL_CODE_BUFFER_LEN];
		unsigned int target_eip_to_stop_execution;

		ptrace (PTRACE_ATTACH, _targetPid, NULL, NULL);
		wait(NULL);
		ptrace (PTRACE_GETREGS, _targetPid, NULL, &regs);
		memcpy((void*)&old_regs, (void*)&regs, sizeof(regs));
		//backup memory
		ptrace_read(_targetPid, regs.eip, backup_memory_buffer, SHELL_CODE_BUFFER_LEN);

		target_eip_to_stop_execution = old_regs.eip + SHELL_CODE_BUFFER_LEN -2 ; //we wnat to stop at the last one-byte instruction which is RET
		//char* shellCodeToExecute = completeShellCode::getShellCodeCall_dlopen_i386((void*)0xf7fb49c0, string("./lib_proxy_open_inject.so"));	
		char* shellCodeToExecute = completeShellCode::getShellCodeCall_dlopen_i386((void*)0xf7fb3ca0, string("./lib_proxy_open_inject.so"));	
		ptrace_write(_targetPid, regs.eip, (void*)shellCodeToExecute, SHELL_CODE_BUFFER_LEN);
		
		while(regs.eip != target_eip_to_stop_execution)
		{
			ptrace(PTRACE_SINGLESTEP, _targetPid, 0, 0);
			wait(NULL);
			ptrace(PTRACE_GETREGS, _targetPid, NULL, &regs);
		}
		
		_logger("done execution!");
		ptrace(PTRACE_SETREGS, _targetPid, NULL, &old_regs);
		_logger("brought back the registers");
		ptrace_write(_targetPid, old_regs.eip, (void*)backup_memory_buffer, SHELL_CODE_BUFFER_LEN);
		_logger("wrote back the memory");
		ptrace(PTRACE_DETACH, _targetPid, NULL, NULL);

	}
	
		
	
	
private:
	const size_t _JUMP_SIZE;
	const unsigned long _targetPid;
	const uint32_t _injection_addr;
	LoggerFunctionPtr _logger=nullptr;
	char* const _traceeMemoryImageBuffer=nullptr;
	
	void ptrace_write(int pid, unsigned long addr, void *vptr, int len)
	{
		int byteCount = 0;
		long word = 0;

		while (byteCount < len)
		{
			memcpy(&word, (void*)((char*)vptr + byteCount), sizeof(word));
			word = ptrace(PTRACE_POKETEXT, pid, (void*)((unsigned int)addr + byteCount), word);
			cout << "written " << byteCount << " bytes \n";
			if(word == -1)
			{
				fprintf(stderr, "ptrace(PTRACE_POKETEXT) failed\n");
				exit(1);
			}
			byteCount += sizeof(word);
		}
	}

	void ptrace_read(int pid, unsigned long addr, void *vptr, int len)
	{
		int bytesRead = 0;
		int i = 0;
		long word = 0;
		long *ptr = (long *) vptr;

		while (bytesRead < len)
		{
			word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytesRead, NULL);
			if(word == -1)
			{
				fprintf(stderr, "ptrace(PTRACE_PEEKTEXT) failed\n");
				exit(1);
			}
			bytesRead += sizeof(word);
			ptr[i++] = word;
		}
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
	
	return MyArgs(argv[1], argv[2], argv[3]); //very simple and minimal args class
}

int main(int argc, char* argv[])
{
	cout << "Run Me With sudo (!) " << endl;
	MyArgs args = validateArgs(argc, argv);
	Injector32 injector(args.pid(), args.injection_addr(), logerToStdOut);
	injector.injectSharedObject(args.sharedObject());

}

