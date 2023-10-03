'''
Implementación del ataque bit-flipping attack del modo CBC.

Autor: Daysapro.
'''


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import urandom
from hashlib import sha1


BLOCK_SIZE = 16
key = urandom(BLOCK_SIZE)
iv = urandom(BLOCK_SIZE)
secret = b"flag{bit_flipping_attack}"

def aes_cbc_encrypt(key, input, iv):
    hash = sha1()
    hash.update(str(key).encode('ascii'))
    key = hash.digest()[:BLOCK_SIZE]
    cipher =  AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(input, BLOCK_SIZE))

def aes_cbc_decrypt(key, input, iv):
    hash = sha1()
    hash.update(str(key).encode('ascii'))
    key = hash.digest()[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(input), BLOCK_SIZE)


print("Nombre de usuario:")
user = input()
print("Contraseña:")
password = input()

query = b"user=" + user.encode() + b"&password=" + password.encode() + b"&admin=0"
encrypted_query = aes_cbc_encrypt(key, query, iv)
print("Petición:")
print(encrypted_query)

padding = len(encrypted_query) - len(query)
i_byte = encrypted_query[-(padding + 1 + BLOCK_SIZE)] ^ 0
new_byte = i_byte ^ 1
new_encrypted_query = list(encrypted_query)
new_encrypted_query[-(padding + 1 + BLOCK_SIZE)] = new_byte

query = aes_cbc_decrypt(key, bytes(new_encrypted_query), iv)
print("Petición descrifrada (en el lado del servidor):")
print(query)

if int(query[-1:]) == 1:
    print(secret)
else:
    exit(1)