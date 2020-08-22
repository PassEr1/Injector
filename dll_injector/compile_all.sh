g++ injector.cpp -std=c++11 -m32 -I ./open_source_code/ -o injector \
./open_source_code/hde32.o

g++ -I ./open_source_code/ -m32 -shared -o lib_proxy_open_inject.so -fPIC -g -Wall \
proxy_injector_dll.cpp \
hook_performer.cpp \
hook_base.cpp \
memory_map_guard.cpp \
memory_protection_context.cpp ./open_source_code/hde32.c

