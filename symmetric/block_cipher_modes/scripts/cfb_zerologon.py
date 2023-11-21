'''
Demostración de la generación de mensaje cifrado entero de ceros de la vulnerabilidad Zerologon.

Autor: Daysapro.
'''


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import urandom
from hashlib import sha1


BLOCK_SIZE = 16
iv = b'\x00'*16
m = b'\x00'*8

def aes_cfb_encrypt(key, input, iv):
    hash = sha1()
    hash.update(str(key).encode('ascii'))
    key = hash.digest()[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.encrypt(input)


for _ in range(1000):
    key = urandom(BLOCK_SIZE)
    c = aes_cfb_encrypt(key, m, iv)
    if c == b'\x00'*8:
        print(f"Clave encontrada: {key}")
