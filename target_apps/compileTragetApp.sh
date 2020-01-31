g++ -I ../dll_injector/shellcodes/ \
	main.cpp\
	 -g -m32 -ldl -o monitor_file_debugable
