#include "debugger.hpp"
#include <exception>
#include <cstring>

Debugger32Bit::Debugger32Bit(long pid):
	_pid(pid)
{
	static void* RESERVED = NULL;
	my_ptrace (PTRACE_ATTACH, _pid, RESERVED, RESERVED);
	
	static int* WAIT_TRACEE  = NULL;
	wait(WAIT_TRACEE);
}

Debugger32Bit::~Debugger32Bit()
{
	try
	{
		static void* RESERVED = NULL;
		my_ptrace(PTRACE_DETACH, _pid, RESERVED, RESERVED);	
	}
	catch(...)
	{}
}

long Debugger32Bit::my_ptrace(enum __ptrace_request request, pid_t pid,
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

struct user_regs_struct Debugger32Bit::get_regs() const
{
	struct user_regs_struct regs;
	static void* RESRVED = NULL;
	my_ptrace(PTRACE_GETREGS, _pid, RESRVED, &regs);
	return regs;
}

std::vector<uint8_t> Debugger32Bit::read_memory(uint32_t address, uint32_t len) const
{
	if((len % sizeof(uint32_t)) != 0)
	{
		throw std::exception();
	}

	std::vector<uint8_t> buffer(len);
	uint32_t *ptr = reinterpret_cast<uint32_t*>(buffer.data()); //explicitness is important here! (and always)
	
	int bytesRead = 0;
	int i = 0;
	long word = 0;

	while (bytesRead < len)
	{
		static void* RESRVED = NULL;
		word = my_ptrace(PTRACE_PEEKTEXT, _pid, reinterpret_cast<void*>(address + bytesRead), RESRVED);
		if(word == -1)
		{
			throw std::exception();
		}
		
		bytesRead += sizeof(word);
		ptr[i++] = word;
	}
	
	return buffer;
}


void Debugger32Bit::write_data(uint32_t address, const uint8_t* const data, uint32_t len)
{
	if(data == nullptr)
	{
		throw std::exception();
	}
	
	int byteCount = 0;
	long word = 0;

	while (byteCount < len)
	{
		memcpy(&word, data + byteCount, sizeof(word));
		word = my_ptrace(PTRACE_POKETEXT, _pid,  reinterpret_cast<void*>(address + byteCount), reinterpret_cast<void*>(word));		
		byteCount += sizeof(word);
	}		
}

void Debugger32Bit::set_regs(struct user_regs_struct& regs)
{
	static void* RESRVED = NULL;
	my_ptrace(PTRACE_SETREGS, _pid, RESRVED, &regs);
}


void Debugger32Bit::step()
{
	static int* RESERVED = 0;
	my_ptrace(PTRACE_SINGLESTEP, _pid, RESERVED, RESERVED);
	
	static int* WAIT_TRACEE  = NULL;
	wait(WAIT_TRACEE);
}
