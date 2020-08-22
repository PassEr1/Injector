#pragma once
#include <cstddef>

class MemoryProtectionContext
{

public:
	virtual ~MemoryProtectionContext();
	
public:
	MemoryProtectionContext(const MemoryProtectionContext&) = delete;
	MemoryProtectionContext& operator=(const MemoryProtectionContext&) = delete;

public:
	static void change_memory_mode(void* addr, const size_t length, int prot);

	
protected:
	MemoryProtectionContext(void* addr, const size_t size);
	
protected:
	const size_t _size;
	void* _addr;
	
private:
	static void* _roundDownToPageBoundary(void* addr);

};


class MemoryProtectionWriteContext final:
	public MemoryProtectionContext
{
public:
	MemoryProtectionWriteContext(void* addr, const size_t size);
};

class MemoryProtectionReadContext final:
	public MemoryProtectionContext
{
public:
	MemoryProtectionReadContext(void* addr, const size_t size);
};
