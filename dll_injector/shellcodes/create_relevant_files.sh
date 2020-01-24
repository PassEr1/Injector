nasm -f elf32 -o temp_injection_as_object.o ./dll_injection.asm
ld -s -m elf_i386 -o shell temp_injection_as_object.o
