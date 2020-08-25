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
	void ptrace_write(int pid, unsigned long addr, const uint8_t* const buffer, int len);
	void ptrace_read(int pid, unsigned long addr, std::vector<uint8_t>& buffer, int len);

private:
	static long my_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
	
private:
	const unsigned long _targetPid;
	const uint32_t _address_of_function_to_hook;
	LoggerFunctionPtr _logger;
};
