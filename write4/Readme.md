Solution
========

Info
====

This challenge was the first one where the main attack functions were not in the main binary

rz-bin
```asm
[Info]
arch     x86
cpu      N/A
baddr    0x00400000
binsz    0x00001979
bintype  elf
bits     64
compiler GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
endian   LE
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x00000000
lang     c
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
os       linux
pcalign  0
relro    partial
rpath    .
subsys   linux
stripped false
va       true
static   false
canary   false
PIE      false
RELROCS  true
NX       true
```

afl, shortend for clarity
```asm
[0x00400520]> afl
0x00400520    1 42           entry0
0x00400617    1 17           sym.usefulFunction
0x00400510    1 6            sym.imp.print_file
0x00400607    1 16           main
0x00400500    1 6            sym.imp.pwnme
[0x00400520]>
```

exerpt from the .plt
```asm
┌ sym.imp.pwnme();
└      ╎╎   0x00400500      jmp   qword reloc.pwnme                    ; [0x601018:8]=0x400506
       ╎╎   0x00400506      push  0
       └──< 0x0040050b      jmp   sym..plt
        ╎   ; CALL XREF from sym.usefulFunction @ 0x400620
┌ sym.imp.print_file();
└       ╎   0x00400510      jmp   qword reloc.print_file               ; [0x601020:8]=0x400516
        ╎   0x00400516      push  1                                    ; 1
        └─< 0x0040051b      jmp   sym..plt
            ;-- section..text:
            ;-- .text:
            ;-- _start:
```

Exploration
===========

This binary is different than the last ones because the vulnerable functions are not included in the binary but are instead a library outside of it. 
The normal helping strings that we present in the past also aren't there. 
This means that the all the helper strings and functions are now going to be manually built and called. This does make things a little more challenging.

We need to call the print_file function in order to print the function. Inorder to get the string *"flag.txt"* as a argument for print_file, we need
to build the rop chain like so,

```
the usual       rdi is the first arg        move "flag.txt" into the area at .data address      build space and store .data addr for call
|---------------|--------------|\   /|------------|------------|--------------------------------|------------|---------------|-----------------|
| Padding ('A') | pop rdi; ret | \ / | .data addr | "flag.txt" | mov qword ptr [r14], r15; ret; | pop rdi    |  .data addr   | call print_file | 
|---------------|--------------| / \ |------------|------------|--------------------------------|------------|---------------|-----------------|
```

We need to find the addresses that fill out this chain.

pop rdi; ret: 0x400690
pop rdi: 0x400693
.data: 0x601028

Eploitation
===========

There are two exloits for this one. I tried to write one in C and it wasn't working and I wanted to make a poc for now. For the time being I wrote the exploit in python aswell.
They are named exploit.c and exploit.py.

