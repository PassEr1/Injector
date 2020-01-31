#!/usr/bin/env python

import sys
import subprocess

LINE_OF_INTEREST = 7
def main(argv):
	if len(argv) < 3:
		print("Invalid usage! \n <binFile> <terminator-eof> \nExample:  ./extract_shell_code.py ./bin_shell 99")
		sys.exit(1)
	output = subprocess.check_output("objdump -D {}".format(argv[1]), shell=True).splitlines()
	shell_code = []
	for line in output[LINE_OF_INTEREST:]:
		op_codes = line.split("\t")[1].strip()
		partial_shellcode = ( "\\x" + "\\x".join(op_codes.split(' ')))
		if partial_shellcode != "\\x{}".format(argv[2]):
			shell_code.append(partial_shellcode)
		else:
			break
	print ''.join(shell_code)
		
main(sys.argv)
		
