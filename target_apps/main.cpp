
#define _GNU_SOURCE 
#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
#include <stdlib.h>
#include "dlfcn.h"
#include <stdio.h>

#include "shellcode_builder_handler.h"

using namespace std;

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		cout << "Usage: <some-text-file>\n";	
	}
	else
	{
		//void * library_handler = dlopen("/home/amit/Desktop/Projects/Injector/dll_injector/lib_proxy_open_inject.so", RTLD_NOW); // A line that simulates the dll injection somewhere in the code.
		void* exit_addr = dlsym(RTLD_NEXT, "dlopen");
		cout << "MY PID IS " << getpid() << " address of dlopen is: " << exit_addr << endl;

		//char* shellCodeToExecute = completeShellCode::getShellCodeCall_dlopen_i386((void*)0xf7fb3ca0, string("./lib_proxy_open_inject.so"));	
		//(( void (*)(void))shellCodeToExecute)();

		cout << "here is the files content: \n";
		while(true)
		{
			ifstream fileToRead(argv[1]);
			if(fileToRead.good())
			{
				string line;
				while (std::getline(fileToRead, line))
				{
					//cout << line << endl;
				}
				
				fileToRead.close();
				usleep(1000);
				//system("clear");
			}
			
		}
		cout << endl;	
	}
	
}
