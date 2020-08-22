#include "memory_protection_context.hpp"
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

void* MemoryProtectionContext::_roundDownToPageBoundary(void* addr)
{
	static uint32_t pagesize = sysconf(_SC_PAGE_SIZE);
	return (void*)((uint32_t)addr & ~(pagesize - 1));
}

void MemoryProtectionContext::change_memory_mode(void* addr, const size_t length, int prot)
{
	const int status = mprotect(
		_roundDownToPageBoundary((void*)addr),
       	length,
       	PROT_READ | PROT_EXEC);
	       	
	static const int FAILED = -1;
	if(status == FAILED)
	{
		throw std::exception();
	}	
}


MemoryProtectionContext::MemoryProtectionContext(void* addr, const size_t size)
:_size(size),
_addr(addr)
{
	change_memory_mode(_addr, _size, PROT_READ | PROT_EXEC);	
}

MemoryProtectionContext::~MemoryProtectionContext()
{
	try
	{
		change_memory_mode(_addr, _size, PROT_READ | PROT_EXEC);
	}
	catch(...)
	{}
}
