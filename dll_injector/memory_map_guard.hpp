#include <cstdint>

class MemoryMapGuard final
{

public:
	MemoryMapGuard(const uint32_t size, const int protection);
	~MemoryMapGuard();
	
public:
	MemoryMapGuard(const MemoryMapGuard&) = delete;
	MemoryMapGuard& operator=(const MemoryMapGuard&) = delete;
	
public:
	void* get_data();
	
private:
	static void* allocate_memory(const uint32_t size, const int protection);
	static void free_memory(void* addr, const uint32_t size);
	
private:
	uint32_t _size;
	void* _mapped_memory;	
};
