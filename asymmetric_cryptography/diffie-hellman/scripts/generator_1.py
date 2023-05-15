'''
Implementación del ataque MITM si g = 1.

Esta implementación resuelve una parte del reto 35 del grupo 5 de retos de cryptopals: https://cryptopals.com/sets/5/challenges/35.

Autor: Daysapro.
'''


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import urandom
from hashlib import sha1
from diffie_hellman import generate_private_key, generate_public_key, generate_shared_key


p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
p = int(p, 16)

g = 2
a = generate_private_key(1024)
A = generate_public_key(a, g, p)

g = 1
b = generate_private_key(1024)
B = generate_public_key(b, g, p)

Sa = generate_shared_key(a, B, p)

print("El número p es: {p}".format(p=p))
print("La clave pública de Bob es: {B}".format(B=B))
print("La clave compartida para Alicia es (maliciosa): {S}".format(S=Sa))

m = b"Hola Bob! He descubierto el repositorio Cryptonomicon y estoy aprendiendo mucho de criptografia!"

hash = sha1()
hash.update(str(Sa).encode('ascii'))
key = hash.digest()[:16]
iv = urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)

c = cipher.encrypt(pad(m, 16))

print("El mensaje cifrado de Alicia es: {c}".format(c=c))

S = 1
hash = sha1()
hash.update(str(S).encode('ascii'))
key = hash.digest()[:16]
cipher2 = AES.new(key, AES.MODE_CBC, iv)

m2 = cipher2.decrypt(c)
m2 = unpad(m2, 16)

print("El mensaje recuperado de Alicia con S = 1 es: {m2}".format(m2=m2))