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


Injector32::Injector32(unsigned long targetPid, uint32_t address_of_function_to_hook,LoggerFunctionPtr _fpLogger):
_targetPid(targetPid),
_address_of_function_to_hook(address_of_function_to_hook),
_logger(_fpLogger)
{
	_logger("Indicators has been initiated.");
}
	
Injector32::~Injector32()
{

}
		
void Injector32::injectSharedObject(const std::string& pathOfDll)
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

	target_eip_to_stop_execution = old_regs.eip + SHELL_CODE_BUFFER_LEN -2 ; //we want to stop at the last one-byte instruction which is RET
	char* shellCodeToExecute = completeShellCode::getShellCodeCall_dlopen_i386((void*)_address_of_function_to_hook, pathOfDll);	
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

	
	
	
bool Injector32::_loadTraceeMemoryImage(std::vector<uint8_t>& imageBuffer, void* startAddr, size_t length)const
{
	if(!imageBuffer.size())
	{
		_logger("Could not copy memory image of target process to buffer!");
		throw std::exception();	
	}
	
	uint32_t currentImageSize = 0;
	uint32_t offsetFromStart = 0;
	
	while(currentImageSize < length)
	{
		long inst = ptrace(
			PTRACE_PEEKTEXT,
			_targetPid,
        (void*)((uint32_t)startAddr + offsetFromStart),
        NULL);
		memcpy(
   		imageBuffer.data() + offsetFromStart,
   		&inst,
   		sizeof(inst));
   
   offsetFromStart += sizeof(inst);
   currentImageSize += sizeof(inst);
	}
	
	return true;
}
	



