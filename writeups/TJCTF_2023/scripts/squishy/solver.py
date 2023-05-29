from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes


r = remote('tjc.tf',31358)

n = int(r.recvline().decode('utf-8').strip())
e = 65537

m = b'admin'
m = bytes_to_long(m)

m1 = 7

r.recvuntil(b': ')
r.sendline(b'new')
r.recvuntil(b': ')
r.sendline(long_to_bytes(m1))
s1 = int(r.recvline().split(b' ')[-1].strip())

m2 = m * pow(m1, -1, n) % n

r.recvuntil(b': ')
r.sendline(b'new')
r.recvuntil(b': ')
r.sendline(long_to_bytes(m2))

s2 = int(r.recvline().split(b' ')[-1].strip())

s = (s1 * s2) % n

r.recvuntil(b': ')
r.sendline(b'login')
r.recvuntil(b': ')
r.sendline(long_to_bytes(m))
r.recvline()
r.sendline(long_to_bytes(s))

print(r.recvall())