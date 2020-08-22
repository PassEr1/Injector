#pragma once
#include <iostream>
#include <stdint.h>
#include <string>
#include <vector>
#include <cstdint>
#include "memory_map_guard.hpp"

namespace ProxyFunctions
{
	int proxy__libc_open (const char *file, int flags);
}


class HookWriter final
{

public:
	enum Proxies{GLIBC_OPEN};
	
public:
	using LoggerFunctionPtr = void (*)(const std::string&);
	
public:
	HookWriter(void* injection_addr, Proxies proxy_choosen, LoggerFunctionPtr fpLogger);
	~HookWriter();
public:
	void run();	
	
private:
	const uint32_t _injection_addr;
	const uint32_t _proxy_function;
	LoggerFunctionPtr _logger;
	std::vector<uint8_t> _memoryImageBuffer;
	MemoryMapGuard _original_code_and_jmp_to_proxy;//AKA trampoline
	
private:
	static uint32_t _getProxyByFlag(Proxies proxy_choosen);
	
private:
	void _writeTheHook();
	int _getHowManyBytesToSave()const;
	void _buildTrampoline(int bytesToBackupCount);
	void _loadTraceeMemoryImage(std::vector<uint8_t>& imageBuffer, void* startAddr)const;
};



