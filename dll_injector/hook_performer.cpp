#include "hook_performer.hpp"
#include <iostream>
#include <fcntl.h>
#include <exception>
#include "hook_base.hpp"


void HookPerformer::logger_to_std_out(const std::string& logMsg)
{
	std::cout << "[>> log message <<] " << logMsg << std::endl;
}

void HookPerformer::hook_glibc_open_function()
{
	try
	{
		HookSetBase hookSetBase((void*)open, HookSetBase::Proxies::GLIBC_OPEN, HookPerformer::logger_to_std_out);
		hookSetBase.hook();
	}
	catch(const std::exception&)
	{
		logger_to_std_out("hook failed");
	}
	
}

