#pragma once
#include <string>

class MyArgs final//very simple and minimal args class (boost's module would have been cool, but unneeded at the moment)
{
public:
	MyArgs(char* _pid, std::string _injection_addr, std::string sharedObject);
	~MyArgs() = default;
	MyArgs(const MyArgs&) = default;
	
public:
	MyArgs& operator=(const MyArgs&) = delete;	

public:
	unsigned long pid() const;
	uint32_t injection_addr() const;
	std::string sharedObject() const;
	
private:
	unsigned long _pid;
	std::string _sharedObject;
	uint32_t _injection_addr;
};
