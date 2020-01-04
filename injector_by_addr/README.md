ASLR should be TURNED OFF !!!!

working code as pseudo code:
-----------------------------------------------------------------


Int Original(int &x)
{
Jmp addrOfatrampoline
...
}

Trampoline()//asm
{

Call proxy
Ret
}

Int Proxy(int & x)
{
X = pasten;
Auto a =(void(*)(int &))exutetefirstN(x);


Return a+1;

}
ExecutefirstN = [someOriginal,e9, original+N]

---------------------------------------------------------------------
