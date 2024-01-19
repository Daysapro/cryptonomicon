'''
Implementación del ataque Hastad's Broadcast con e = 3.
 
Autor: Daysapro.
'''
 
 
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
from sympy import root
 
 
p1 = getPrime(2048)
q1 = getPrime(2048)
n1 = p1 * q1
p2 = getPrime(2048)
q2 = getPrime(2048)
n2 = p2 * q2
p3 = getPrime(2048)
q3 = getPrime(2048)
n3 = p3 * q3
e = 3
secret = b"flag{hastads_broadcast_attack}"
 
c1 = pow(bytes_to_long(secret), e, n1)
c2 = pow(bytes_to_long(secret), e, n2)
c3 = pow(bytes_to_long(secret), e, n3)
print(f"Texto cifrado 1: {str(c1)}")
print(f"Texto cifrado 2: {str(c2)}")
print(f"Texto cifrado 3: {str(c3)}")
 
 
N = n1 * n2 * n3
b1 = N // n1
b2 = N // n2
b3 = N // n3
m = (c1 * b1 * pow(b1, -1, n1) + c2 * b2 * pow(b2, -1, n2) + c3 * b3 * pow(b3, -1, n3)) % N
 
print(long_to_bytes(root(m, 3)))