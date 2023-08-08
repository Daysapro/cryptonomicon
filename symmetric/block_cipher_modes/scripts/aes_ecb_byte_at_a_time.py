'''
Implementación del ataque Byte-at-a-time del modo ECB con la entrada concatenada al inicio.

Autor: Daysapro.
'''


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
from hashlib import sha1


secret = b"flag{byte_at_a_time_attack}"

def aes_ecb(key, input):
    plaintext = input + secret
    hash = sha1()
    hash.update(str(key).encode('ascii'))
    key = hash.digest()[:16]
    cipher =  AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, 16))


key = urandom(16)

guessed_secret = b""
n_block = 0

while True:
    for i in range(15, -1, -1):
        input = b"A" * i
        reference_block = aes_ecb(key, input)[16 * n_block:16 + 16 * n_block]
        
        if reference_block == b"":
            exit(1)
        
        for character in range(256):
            input = b"A" * i + guessed_secret + chr(character).encode()
            block = aes_ecb(key, input)[16 * n_block:16 + 16 * n_block]

            if reference_block == block:
                guessed_secret += chr(character).encode()
                print(guessed_secret)
                break
    n_block += 1