#include <iostream>
#include "injector.hpp"
#include "args.hpp"
#include "injector.hpp"

void logerToStdOut(const std::string& logMsg);
MyArgs validateArgs(int argc, char* argv[]);

void logerToStdOut(const std::string& logMsg)
{
	std::cout << "[>> log message << ] " << logMsg << std::endl;
}


MyArgs validateArgs(int argc, char* argv[])
{
	if(argc < 4)
	{
		std::cout << "Wrong Args!\n	Usage: [PID] [TARGET_ADDRESS] [SHARED_OBJ]\n";
		throw std::exception();
	}
	
	return MyArgs(argv[1], argv[2], argv[3]); //very simple and minimal args class
}


int main(int argc, char* argv[])
{
	std::cout << "Run Me With sudo (!) " << std::endl;
	MyArgs args = validateArgs(argc, argv);
	try
	{
		Injector32 injector(args.pid(), args.injection_addr(), logerToStdOut);
		injector.injectSharedObject(args.sharedObject());
	}
	catch(...)
	{
		logerToStdOut("injection failed!");
	}	
}

