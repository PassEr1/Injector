#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "hook_base.h"

using namespace std;

void logerToStdOut(std::string logMsg)
{
	cout << "[>> log message << ] " << logMsg <<endl;
}

void hook_Glibc_OpenFunction()
{
	HookSetBase hookSetBase((void*)open, HookSetBase::Proxies::GLIBC_OPEN, logerToStdOut);
	hookSetBase.inject_to_libc_open();
}


void __attribute__ ((constructor)) my_init(void)
{
	system("touch marker.txt");
	cout << "library loaded!!! \n\n";
	hook_Glibc_OpenFunction();
	
}


void __attribute__ ((destructor)) my_fini(void)
{

}
