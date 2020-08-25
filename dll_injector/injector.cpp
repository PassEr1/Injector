#include "injector.hpp"
#include <exception>
#include <sys/ptrace.h>
#include<sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include "shellcodes/shellcode_builder_handler.h"
#include "config.hpp"
//open source
#include "hde32.h"


Injector32::Injector32(unsigned long targetPid, uint32_t injection_addr,LoggerFunctionPtr _fpLogger):
_JUMP_SIZE(5),
_traceeMemoryImageBuffer(new char[Consts::MAX_POSSIBLE_TRAMPOLINE_SIZE]),
_targetPid(targetPid),
_injection_addr(injection_addr),
_logger(_fpLogger)
{
	_loadTraceeMemoryImage(_traceeMemoryImageBuffer, (void*)_injection_addr, Consts::MAX_POSSIBLE_TRAMPOLINE_SIZE);
	_logger("Indicators has been initiated.");
}
	
Injector32::~Injector32()
{
	delete _traceeMemoryImageBuffer;
	_logger("Been there done that.");
}
		
void Injector32::injectSharedObject(string pathOfShared)
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
void Injector32::ptrace_write(int pid, unsigned long addr, void *vptr, int len)
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

void Injector32::ptrace_read(int pid, unsigned long addr, void *vptr, int len)
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

	
	
	
bool Injector32::_loadTraceeMemoryImage(char* imageBuffer, void* startAddr, size_t length)const
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
	



