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
#include <sys/reg.h>
#include "shellcodes/shellcode_builder_handler.h"
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
		sharedObject = sharedObject;
			
	}
	unsigned long pid;
	uint32_t injection_addr;
	string sharedObject;
	
};


class Injector32
{

public:
	Injector32(unsigned long targetPid, uint32_t injection_addr,LoggerFunctionPtr _fpLogger)
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
	
	~Injector32()
	{
		delete _traceeMemoryImageBuffer;
		_logger("Been there done that.");
	}
	

	
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
	char* _original_code_and_jmp_to_target_plus_N=nullptr;//AKA trampoline
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

int main(int argc, char* argv[])
{
	cout << "Run Me With sudo (!) " << endl;
	MyArgs args = validateArgs(argc, argv);
	Injector32 nurse(args.pid, args.injection_addr, logerToStdOut);
	nurse.injectSharedObject(args.sharedObject);

}

