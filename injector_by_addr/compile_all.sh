#g++ main.cpp -std=c++11 -m32 -I ./open_source_code/ -o injector \
#./open_source_code/hde32.o

g++ -shared -o lib_proxy_open_inject.so -fPIC -g -Wall proxy_open_self_injection.cpp

