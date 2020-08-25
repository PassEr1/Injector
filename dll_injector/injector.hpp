#pragma once
#include <string>
#include <cstdint>
#include <vector>
#include <sys/ptrace.h>

using LoggerFunctionPtr = void (*)(const std::string&);	

class Injector32 final
{
public:
	Injector32(unsigned long targetPid, uint32_t injection_addr,LoggerFunctionPtr _fpLogger);
	~Injector32();
	Injector32(const Injector32&) = delete;
	Injector32& operator=(const Injector32&) = delete;
	
public:
	void injectSharedObject(const std::string& pathOfDll);
	
private:
	const unsigned long _targetPid;
	const uint32_t _address_of_function_to_hook;
	LoggerFunctionPtr _logger;
};
