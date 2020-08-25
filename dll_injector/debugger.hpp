#pragma once
#include <sys/ptrace.h>
#include<sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <cstdint>
#include <vector>

class Debugger32Bit final
{
public:
	Debugger32Bit(long pid);
	~Debugger32Bit();
public:
	Debugger32Bit(const Debugger32Bit&) = delete;
	Debugger32Bit& operator=(const Debugger32Bit&) = delete;
	
public:
	struct user_regs_struct get_regs() const;
	std::vector<uint8_t> read_memory(uint32_t address, uint32_t len) const ;
	void write_data(uint32_t address, const uint8_t* const data, uint32_t len);
	void set_regs(struct user_regs_struct& regs);
	
private:
	static long my_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);	

private:
	long _pid;
};
