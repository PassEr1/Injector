#pragma once
#include <iostream>
#include <stdint.h>
#include <string>
#include <vector>
#include <cstdint>

namespace ProxyFunctions
{
	int proxy__libc_open (const char *file, int flags);
}


class HookSetBase
{

public:
	enum Proxies{GLIBC_OPEN};
	
public:
	using LoggerFunctionPtr = void (*)(const std::string&);
	
public:
	HookSetBase(void* injection_addr, Proxies proxy_choosen, LoggerFunctionPtr fpLogger);
	~HookSetBase();
public:
	bool inject_to_libc_open();	
	
private:
	const size_t _JUMP_SIZE;
	const uint32_t _injection_addr=0;
	const uint32_t _proxy_function=0;
	LoggerFunctionPtr _logger=nullptr;
	char* _original_code_and_jmp_to_target_plus_N=nullptr;//AKA trampoline
	std::vector<uint8_t> _memoryImageBuffer;
	
private:
	void _writeTheHook();
	char* _alloc_for_trampoline_executable_space()const;
	uint32_t _get_proxy_by_flag(Proxies proxy_choosen) const;
	int _getHowManyBytesToSave()const;
	void _buildTrampoline(int _NBytesToBackup);
	bool _loadTraceeMemoryImage(std::vector<uint8_t>& imageBuffer, void* startAddr, size_t length)const;
	void* _roundDownToPageBoundary(void* addr)const;
	void _setTargetAddressToRead(size_t length)const;	
	void _setTargetAddressToWrite(size_t length)const;
};



