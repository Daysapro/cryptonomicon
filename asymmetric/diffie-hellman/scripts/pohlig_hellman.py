'''
Implementación de Diffie-Hellman vulnerable a Pohlig-Hellman.

Se genera un número primo vulnerable, siendo p - 1 un número liso, en este caso 7-liso.

La función discrete_log de la librería sympy ejecuta el algoritmo Pohlig-Hellman entre otros, y puede tardar un par de minutos en obtener el resultado. Si intentamos utilizar esta función con un primo seguro no lo obtendremos nunca.

Autor: Daysapro.
'''


from random import choice
from sympy import isprime
from sympy.ntheory import discrete_log
from secrets import randbelow


def generate_vulnerable_prime(n):
    primes = [2, 3, 5, 7]
    i = 1
    while True:
        i *= choice(primes)
        if isprime(i + 1) and i > 2**n:
            return i + 1


def generate_private_key(n):
    return randbelow(2**n)


def generate_public_key(private_key, g, p):
    return pow(g, private_key, p)


p = generate_vulnerable_prime(1024)
g = 2

a = generate_private_key(1024)
print("La clave de Alicia es: {a}".format(a=a))

A = generate_public_key(a, g, p)

a2 = discrete_log(p, A, g)
print("La clave recuperada del logaritmo discreto es: {a2}".format(a2=a2))

assert a == a2