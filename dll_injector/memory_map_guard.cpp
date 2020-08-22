#include "memory_map_guard.hpp"
#include <sys/mman.h>
#include <exception>

void free_memory(void* addr, const uint32_t size)
{
	const int status = munmap(addr, size);
	static const int FAILED = -1;
	if(status == FAILED)
	{
		throw std::exception();
	}
}

void* allocate_memory(const uint32_t size, const int protection)
{
	static void* DEFAULT_ADDR = nullptr;
	static const int DEFAULT_FD = -1;
	static const off_t NO_OFFSET = 0;
	void* status = mmap(DEFAULT_ADDR,
		size,
		protection,
		MAP_ANONYMOUS | MAP_PRIVATE,
		DEFAULT_FD,
		NO_OFFSET);
	static const void* STATUS_FAILED = MAP_FAILED;
	if(status == STATUS_FAILED)
	{
		throw std::exception();
	}
	
	return status;
}

MemoryMapGuard::MemoryMapGuard(const uint32_t size, const int protection)
	:_size(size),
	_mapped_memory(allocate_memory(size, protection))
{
}

MemoryMapGuard::~MemoryMapGuard()
{
	try
	{
		free_memory(_mapped_memory, _size);	
	}
	catch(...)
	{}
}

void* MemoryMapGuard::get_data()
{
	return _mapped_memory;
}

