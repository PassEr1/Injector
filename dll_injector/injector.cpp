#include "injector.hpp"
#include <exception>
#include <sys/ptrace.h>
#include<sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include "shellcodes/shellcode_builder_handler.h"
#include "config.hpp"
#include "debugger.hpp"
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
{}

		
void Injector32::injectSharedObject(const std::string& pathOfDll)
{
	
	struct user_regs_struct regs;
	struct user_regs_struct old_regs;
	std::vector<uint8_t> backup_memory_buffer(SHELL_CODE_BUFFER_LEN);
	unsigned int target_eip_to_stop_execution;
	
	Debugger32Bit debugger(_targetPid);
	my_ptrace(PTRACE_GETREGS, _targetPid, NULL, &regs);
	regs = debugger.get_regs();
	memcpy((void*)&old_regs, (void*)&regs, sizeof(regs));

	//backup memory
	backup_memory_buffer = debugger.read_memory(regs.eip, SHELL_CODE_BUFFER_LEN);

	target_eip_to_stop_execution = old_regs.eip + SHELL_CODE_BUFFER_LEN -2; //we want to stop at the last one-byte instruction which is RET
	uint8_t* shellCodeToExecute = completeShellCode::getShellCodeCall_dlopen_i386((void*)_address_of_function_to_hook, pathOfDll);	
	debugger.write_data(regs.eip, shellCodeToExecute, SHELL_CODE_BUFFER_LEN);
	
	while(regs.eip != target_eip_to_stop_execution)
	{
		my_ptrace(PTRACE_SINGLESTEP, _targetPid, 0, 0);
		wait(NULL);
		my_ptrace(PTRACE_GETREGS, _targetPid, NULL, &regs);
	}
	
	_logger("done execution!");
	debugger.set_regs(old_regs);
	_logger("brought back the registers");
	debugger.write_data(old_regs.eip, backup_memory_buffer.data(), SHELL_CODE_BUFFER_LEN);
	_logger("wrote back the memory");
}
void Injector32::ptrace_write(int pid, unsigned long addr,const uint8_t* const buffer, int len)
{
	int byteCount = 0;
	long word = 0;

	while (byteCount < len)
	{
		memcpy(&word, (void*)(buffer + byteCount), sizeof(word));
		word = my_ptrace(PTRACE_POKETEXT, pid, (void*)((unsigned int)addr + byteCount), reinterpret_cast<void*>(word));
		cout << "written " << byteCount << " bytes \n";
		if(word == -1)
		{
			fprintf(stderr, "ptrace(PTRACE_POKETEXT) failed\n");
			exit(1);
		}
		
		byteCount += sizeof(word);
	}
}

void Injector32::ptrace_read(int pid, unsigned long addr, std::vector<uint8_t>& buffer, int len)
{
	uint32_t *ptr = reinterpret_cast<uint32_t*>(buffer.data()); //explicitness is important here! (and always)
	if(!(buffer.size() % sizeof(uint32_t)))
	{
		_logger("buffer' size is not a multiple of an opcode size");
		throw std::exception();
	}
	
	int bytesRead = 0;
	int i = 0;
	long word = 0;

	while (bytesRead < len)
	{
		word = my_ptrace(PTRACE_PEEKTEXT, pid, reinterpret_cast<void*>(addr + bytesRead), NULL);
		if(word == -1)
		{
			throw std::exception();
		}
		
		bytesRead += sizeof(word);
		ptr[i++] = word;
	}
}
	


long Injector32::my_ptrace(enum __ptrace_request request, pid_t pid,
	           void *addr, void *data)
{
	long status = ptrace(request, pid, addr, data);
	static const long FAIL = -1;
	if(status == FAIL)
	{
		throw std::exception();
	}	
	
	return status;
}
