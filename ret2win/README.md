## Solution

### Initial Recon

I did the x86-64 version of this challenge which I don't think was too different from the x86 version of this
https://ropemporium.com/challenge/ret2win.html

running checksec shows that the binary has NX enabled but has canaries turned off

![checksec](https://github.com/VJMumphrey/rop-emporium-writeups/tree/main/ret2win/images/checksec.png)

### Exploration

After opening the binary in rizin I looked through the functions: main, pwnme, and ret2win. There pictures are as follows

- afl

![afl](https://github.com/VJMumphrey/rop-emporium-writeups/tree/main/ret2win/images/afl.png)

- main

![main](https://github.com/VJMumphrey/rop-emporium-writeups/tree/main/ret2win/images/main.png)

- pwnme

![pwnme](https://github.com/VJMumphrey/rop-emporium-writeups/tree/main/ret2win/images/pwnme.png)

- ret2win

![ret2win](https://github.com/VJMumphrey/rop-emporium-writeups/tree/main/ret2win/images/ret2win.png)

After reading through the disassembly I saw that a buffer of 32 bytes was created chaining this with the strings to be printed, it makes it pretty obvious that this is a normal stackoverflow.
I opened up gdb and generated a pattern and found the offset to ret;.

![offset](https://github.com/VJMumphrey/rop-emporium-writeups/tree/main/ret2win/images/offset.png)

### Generating the Exploit

This might not be the easiest way of doing it but I feel like this is better in the long run. I created the exploit with C. It is included with comments. After running it I got the flag printed

![flag](https://github.com/VJMumphrey/rop-emporium-writeups/tree/main/ret2win/images/flag.png)