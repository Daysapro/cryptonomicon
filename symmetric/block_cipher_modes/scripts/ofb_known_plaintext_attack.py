'''
Implementación del ataque de texto claro conocido al modo OFB.

Autor: Daysapro.
'''


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
from hashlib import sha1


BLOCK_SIZE = 16 
key = urandom(BLOCK_SIZE)
iv = urandom(BLOCK_SIZE)
known = b"Esto es un mensaje del que se conoce su correspondiente cifrado"
secret = b"flag{known_plaintext_attack}"

def aes_ofb_encrypt(key, input, iv):
    hash = sha1()
    hash.update(str(key).encode('ascii'))
    key = hash.digest()[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.encrypt(pad(input, BLOCK_SIZE))


known_ciphertext = aes_ofb_encrypt(key, known, iv)
secret_ciphertext = aes_ofb_encrypt(key, secret, iv)
print(b"Texto en claro: " + known)
print(b"Texto cifrado: " + known_ciphertext)
print(b"Texto cifrado del secreto: " + secret_ciphertext)

i_bytes = b""
for i in range(len(known)):
    i_bytes += chr(known[i] ^ known_ciphertext[i]).encode('iso-8859-1')

flag = ""
for i in range(len(secret_ciphertext)):
    flag += chr(i_bytes[i] ^ secret_ciphertext[i])

print(flag)