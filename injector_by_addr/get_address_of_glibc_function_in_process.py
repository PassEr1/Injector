"""
Example of usage:
get_address_of_glibc_function_in_process.py 113227 printf@@GLIBC_ 32
------
Output: the address of printf@@GLIBC_ is 0x7dead5beef
"""


import sys

CURRENT_PROC_NAME = 0
TARGET_PID = 1
TARGET_GLIBC_FUNCTION_NAME = 2
_64_OR_32_TARGET_FLAG = 3

def get_file_base_address_from_line(line):
	address_range = line.split(" ")[0]
	base_addr = address_range.split("-")[0]
	return base_addr

def get_base_address_of_loaded_libc(target_pid, target_bus_size):
	symbole_should_exists_in_line = "/lib{}/libc-".format(target_bus_size)
	target_address = None
	with open("/proc/{}/maps".format(target_pid)) as proc_maps_file:
		for line in proc_maps_file:
			if symbole_should_exists_in_line in line:
				target_address = get_file_base_address_from_line(line)
				break
	return target_address

def main(argv):
	if len(argv) < 3:
		raise Exception("Wrong number of arguments.\n Usage:\n	[TARGET_PID] [TARGET_GLIBC_FUNCTION_NAME] [64_OR_32_TARGET_FLAG]")
	target_pid = argv[TARGET_PID]
	target_function_name = argv[TARGET_GLIBC_FUNCTION_NAME]
	target_bus_size = "64" if argv[_64_OR_32_TARGET_FLAG] == "64" else "32"
	base_address_of_loaded_libc = get_base_address_of_loaded_libc(target_pid, target_bus_size)
	print("base address is: {}".format(base_address_of_loaded_libc))
	
if __name__ == "__main__":
	main(sys.argv)
