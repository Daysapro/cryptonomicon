'''
Implementación del ataque de la raíz cúbica cuando e = 3 y m^e < n.
 
Se usa la función de root de sympy porque tiene mayor exactitud que cualquier función nativa de Python.
 
Autor: Daysapro.
'''
 
 
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
from sympy import root
 
 
p = getPrime(2048)
q = getPrime(2048)
n = p * q
e = 3
secret = b"flag{cube_root}"
 
c = pow(bytes_to_long(secret), e, n)
print(f"Texto cifrado: {str(c)}")
 
 
print(long_to_bytes(root(c, 3)))