from binascii import crc32
from pwn import *


PASSWORD = b"give me the flag!!!"
crc = crc32(PASSWORD)
m1 = 262857
m2 = 13477
assert crc == m1 * m2

# crc32.py

c1 = b"22p6NE"
c2 = b"2i_pQM"

assert crc32(c1) == m1
assert crc32(c2) == m2

r = remote('signer.chal.imaginaryctf.org',  1337)
r.recvuntil(b"Get flag")
r.sendline(b"1")
r.recvline()
r.recvline()
r.sendline(c1)
s1 = int(r.recvline().decode().strip()[11:])
r.recvline()
r.sendline(b"1")
r.recvline()
r.recvline()
r.sendline(c2)
s2 = int(r.recvline().decode().strip()[11:])
r.recvline()
r.recvline()

s = s1 * s2

r.sendline(b"2")
r.recvline()
r.sendline(str(s).encode())
print(r.recvline())
