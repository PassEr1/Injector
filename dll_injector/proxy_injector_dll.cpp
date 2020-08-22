#include "proxy_injector_dll.hpp"
#include <iostream>
#include <sys/stat.h>
#include <fcntl.h>
#include "hook_base.h"

using namespace std;

void InjectorDll::logger_to_std_out(const std::string& logMsg)
{
	cout << "[>> log message <<] " << logMsg <<endl;
}

void InjectorDll::hook_glibc_open_function()
{
	HookSetBase hookSetBase((void*)open, HookSetBase::Proxies::GLIBC_OPEN, InjectorDll::logger_to_std_out);
	hookSetBase.inject_to_libc_open();
}


void __attribute__ ((constructor)) my_init(void)
{
	system("touch marker.txt"); //basically a debuging file to detrmine if dll was loaded.
	InjectorDll::hook_glibc_open_function();
	
}


void __attribute__ ((destructor)) my_finish(void)
{}
