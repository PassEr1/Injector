#include "args.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>

MyArgs::MyArgs(char* pid, std::string injection_addr, std::string sharedObject):
	_pid(strtoul(pid, nullptr, 10)),
	_sharedObject(sharedObject)
{
	std::istringstream converter(injection_addr);
	converter >> std::hex >> _injection_addr;		
}

unsigned long MyArgs::pid() const
{
	return _pid;
}

uint32_t MyArgs::injection_addr() const
{
	return _injection_addr;
}

std::string MyArgs::sharedObject() const
{
	return _sharedObject;
}
