'''
Implementación del ataque padding oracle attack del modo CBC.

Autor: Daysapro.
'''


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import urandom
from hashlib import sha1


BLOCK_SIZE = 16
key = urandom(16)
iv = urandom(16)
secret = b"flag{padding_oracle_attack}"

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
    cipher =  AES.new(key, AES.MODE_CBC, iv)
    
    try:
        unpad(cipher.decrypt(input), BLOCK_SIZE)
        return "No error"
    except:
        return "Padding error"

ciphertext = aes_cbc_encrypt(key, secret, iv)
print(b"Texto cifrado: " + ciphertext)


flag = ""

for i in range(len(ciphertext) // BLOCK_SIZE):
    ciphertext_block = ciphertext[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
    intermediate_block = [0] * BLOCK_SIZE
    auxiliar_block = [0] * BLOCK_SIZE
    
    for padding in range(1, BLOCK_SIZE + 1):  
        auxiliar_block = [character ^ padding for character in intermediate_block]

        for X in range(256):
            auxiliar_block[-padding] = X
            if aes_cbc_decrypt(key, ciphertext_block, bytes(auxiliar_block)) == "No error":
                if padding == 1:
                    auxiliar_block[-2] ^= 1
                    if aes_cbc_decrypt(key, ciphertext_block, bytes(auxiliar_block)) != "No error":
                        continue
                break

        intermediate_block[-padding] = X ^ padding
    
    for j in range(BLOCK_SIZE):
        if i == 0:
            flag += chr(intermediate_block[j] ^ iv[j])
        else:
            flag += chr(intermediate_block[j] ^ ciphertext[(i - 1) * BLOCK_SIZE:i * BLOCK_SIZE][j])

print(flag)