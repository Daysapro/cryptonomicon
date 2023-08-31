from Crypto.Util.number import long_to_bytes
from base64 import b64decode
from hashlib import sha256


with open("log.txt", "rb") as file:
    log = file.read().decode().split("\n")

enc_flag = b64decode(log[0].split(" \"")[1][:-1].encode())
log = log[1:-1]

h = []
r = []
s = []

for i in range(len(log) // 3):
    h.append(int(log[i * 3].split("= ")[1]))
    r.append(int(log[i * 3 + 1].split("= ")[1]))
    s.append(int(log[i * 3 + 2].split("= ")[1]))

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

d = (h[0] * pow(s[0], -1, n) * s[607] * pow(r[607], -1, n) + h[334] * pow(s[334], -1, n) * s[607] * pow(r[607], -1, n) - h[607] * pow(r[607], -1, n)) * pow(1 - r[0] * pow(s[0], -1, n) * s[607] * pow(r[607], -1, n) - r[334] * pow(s[334], -1, n) * s[607] * pow(r[607], -1, n), -1, n) % n

hash = sha256()
hash.update(long_to_bytes(d))
key = hash.digest()

flag = ""
for i in range(len(enc_flag)):
    flag += chr(enc_flag[i] ^ key[i])

print(flag)