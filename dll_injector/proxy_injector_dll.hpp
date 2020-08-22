#include <string>
	
namespace InjectorDll
{
	void logger_to_std_out(const std::string& logMsg);
	void hook_glibc_open_function();
}
