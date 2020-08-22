#pragma once
#include <cstddef>

class MemoryProtectionContext final
{

public:
	MemoryProtectionContext(void* addr, const size_t size);
	~MemoryProtectionContext();
	
public:
	MemoryProtectionContext(const MemoryProtectionContext&) = delete;
	MemoryProtectionContext& operator=(const MemoryProtectionContext&) = delete;

public:
	static void change_memory_mode(void* addr, const size_t length, int prot);
	
private:
	static void* _roundDownToPageBoundary(void* addr);
	
private:
	const size_t _size;
	void* _addr;
};
