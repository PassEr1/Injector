ASLR should be TURNED OFF !!!!

working code as pseudo code:
-----------------------------------------------------------------


Int Original(int &x)
{
Jmp addrOfatrampoline # 5 bytes worth
 < position 1
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
Auto a =(int(*)(int &))exutetefirstN(x);


Return a+1;

}
ExecutefirstN = [someOriginal,e9, (original+N) ]

                                          ^ position 2
---------------------------------------------------------------------
