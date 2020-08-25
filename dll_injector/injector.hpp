#pragma once
#include <string>
#include <cstdint>
#include <vector>

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
	void ptrace_write(int pid, unsigned long addr, void *vptr, int len);
	void ptrace_read(int pid, unsigned long addr, void *vptr, int len);
	bool _loadTraceeMemoryImage(std::vector<uint8_t>& imageBuffer, void* startAddr, size_t length)const;
	
private:
	const unsigned long _targetPid;
	const uint32_t _injection_addr;
	LoggerFunctionPtr _logger;
	std::vector<uint8_t> _traceeMemoryImageBuffer;
};
