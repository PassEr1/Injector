#include "proxy_injector_dll.hpp"
#include <sys/stat.h>
#include "hook_base.hpp"
#include "hook_performer.hpp"
using namespace std;


void __attribute__ ((constructor)) my_init(void)
{
	system("touch marker.txt"); //basically a debuging file to detrmine if dll was loaded.
	HookPerformer::hook_glibc_open_function();
	
}


void __attribute__ ((destructor)) my_finish(void)
{}
