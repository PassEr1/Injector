#!/usr/bin/env python

"""
Example of usage:
get_address_of_glibc_function_in_process.py 113227 printf@@GLIBC_ 32
------
Output: the address of printf@@GLIBC_ is 0x7dead5beef
"""


import sys
import subprocess
import re

CURRENT_PROC_NAME = 0
TARGET_PID = 1
TARGET_GLIBC_FUNCTION_NAME = 2
_64_OR_32_TARGET_FLAG = 3

INDEX_OF_RELATIVE_OFFSET_INSIDE_RESULT = 3

def get_file_base_address_from_line(line):
	address_range = line.split(" ")[0]
	base_addr = address_range.split("-")[0]
	return base_addr
	
def get_relevant_loaded_libc_from_line(line):
	file_name = line.split(" ")[-1]
	return file_name

def get_base_address_of_loaded_libc(target_pid, target_bus_size):
	symbole_should_exists_in_line = "/lib{}/libdl-".format(target_bus_size)
	base_address = None
	file_of_libc = None
	with open("/proc/{}/maps".format(target_pid)) as proc_maps_file:
		for line in proc_maps_file:
			if symbole_should_exists_in_line in line:
				base_address = get_file_base_address_from_line(line)
				file_of_libc = get_relevant_loaded_libc_from_line(line)
				break
	return "0x{}".format(base_address), file_of_libc
	
	
def is_found_target_function(optional_function_name, target_function_name):
	return optional_function_name.startswith(target_function_name)
	
	
def get_offset_of_requested_function(libc_file, target_function_name):
	search_results = None
	try:
		search_results = subprocess.check_output("readelf -Ws {} | grep {}".format(libc_file, target_function_name), shell=True).splitlines()
		assert(len(search_results))
	except:
		raise Exception("Function name does not exists in .so file({})".format(libc_file))
	for res in search_results:
		search_result_parameters = res.split(" ")
		optional_function_name = search_result_parameters[-1]
		if is_found_target_function(optional_function_name, target_function_name):
			return "0x{}".format(re.findall(r": +(\w+) +", res)[0])
	
			
			
def fix_names_for_bash(fname):
	new_fname = fname.replace("\n", "").strip()
	return new_fname
	
def calc_final_address(hex_as_str1, hex_as_str2):
	n1 = int(hex_as_str1 ,16)
	n2 = int(hex_as_str2 ,16)
	return hex(n1 + n2)
	

def main(argv):
	if len(argv) < 4:
		raise Exception("Wrong number of arguments.\n Usage:\n	[TARGET_PID] [TARGET_DL_FUNCTION_NAME] [64_OR_32_TARGET_FLAG] \n Example: get_address_of_glibc_function_in_process.py 64977 dlopen@@GLIBC 32")
	target_pid = argv[TARGET_PID]
	target_function_name = argv[TARGET_GLIBC_FUNCTION_NAME]
	target_bus_size = "64" if argv[_64_OR_32_TARGET_FLAG] == "64" else "32"
	base_address_of_loaded_libc, file_of_libc = get_base_address_of_loaded_libc(target_pid, target_bus_size)
	offset_of_requested_function = get_offset_of_requested_function(fix_names_for_bash(file_of_libc), target_function_name)
	print("base address is: {}".format(base_address_of_loaded_libc))
	print("offset of requested function is: {} ".format(offset_of_requested_function))
	print("final address of the target function is: {}".format(calc_final_address(base_address_of_loaded_libc, offset_of_requested_function)))
	
if __name__ == "__main__":
	main(sys.argv)
