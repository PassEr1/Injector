

#include <iostream>
#include <stdint.h>
#include <string>
#include <exception>
#include <stdlib.h>
#include <sstream>
#include <iomanip>

using namespace std;
using LoggerFunctionPtr = void (*)(std::string);


void logerToStdOut(std::string logMsg)
{
	cout <<"[>> log message << ] " << logMsg <<endl;
}

namespace proxies
{
	int proxy__libc_open (const char *file, int oflag)
	{
		//Auto a =(int(*)(int &))exutetefirstN(x);
		return -1;
	}
}



class MyArgs
{
public:
	MyArgs(char* _pid, char* _injection_addr)
	{
		pid = strtoul(_pid, nullptr, 10);
		std::istringstream converter(_injection_addr);
		converter >> std::hex >> injection_addr;
			
	}
	unsigned long pid;
	uint32_t injection_addr;
};

class Injector
{

public:
	Injector(unsigned long targetPid, uint32_t injection_addr,LoggerFunctionPtr _fpLogger)
	:_targetPid(targetPid),
	_injection_addr(injection_addr),
	_logger(_fpLogger)
	{
		_logger("Indicators has been initiated.");
	}
	
private:
	const unsigned long _targetPid;
	const uint32_t _injection_addr;
	LoggerFunctionPtr _logger=nullptr;
	char _original_code_and_jnp_to_pus_N[25];

	int get_how_many_bytes_to_save(unsigned long injection_addr)
	{
		(void)injection_addr;
		return 0;
	}

};


MyArgs validateArgs(int argc, char* argv[])
{
	if(argc < 3)
	{
		cout << "Wrong Args!\n	Usage: [PID] [TARGET_ADDRESS] \n";
		throw exception();
	}
	
	return MyArgs(argv[1], argv[2]);	
}

int main(int argc, char* argv[])
{
	MyArgs args = validateArgs(argc, argv);
	Injector nurse(args.pid, args.injection_addr, logerToStdOut);
	std::cout << "Done!! \n";
}








