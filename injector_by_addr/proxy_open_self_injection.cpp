#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#include "hook_base.h"

using namespace std;

int proxy__libc_open (const char *file, int oflag)
{
	cout << "inside the proxy function!!! \n";
	//int resOfOrigin =(int(*)(const char*, int ))exutetefirstN(x);
	return -1;
}


void hook_Glibc_OpenFunction()
{
	
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
