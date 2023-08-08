'''
Implementación de un sistema de inicio de sesión que concatena la entrada del usuario con una contraseña candidata y envía los datos usando AES con el modo de operación de cifrado de bloques ECB.

Este sistema sería vulnerable al ataque Byte-at-a-time.

Autor: Daysapro.
'''


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
from hashlib import sha1


password = "admin123"

print("Nombre de usuario: ")
user = input()

query = {"usuario": user, "password": password}

key = urandom(16)
hash = sha1()
hash.update(str(key).encode('ascii'))
key = hash.digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)

ciphertext = cipher.encrypt(pad(str(query).encode(), 16))

print(query)
print(ciphertext)