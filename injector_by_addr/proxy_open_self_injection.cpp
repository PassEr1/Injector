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

namespace proxyies
{
	int proxy__libc_open (const char *file, int oflag)
	{
		cout << "*********       inside the proxy function!!! ************** n\n";
		//int resOfOrigin =(int(*)(const char*, int ))exutetefirstN(x);
		return -1;
	}
}


void hook_Glibc_OpenFunction()
{
	HookSetBase hookSetBase((uint32_t)open, HookSetBase::Proxies::GLIBC_OPEN, logerToStdOut);
	hookSetBase.inject_to_libc_open();
}


void __attribute__ ((constructor)) my_init(void)
{
	system("touch marker.txt");
	cout << "library loaded!!! \n";
	hook_Glibc_OpenFunction();
	
}


void __attribute__ ((destructor)) my_fini(void)
{

}
