'''
Implementación del intercambio de claves Diffie-Hellman.

Esta implementación resuelve el reto 33 del grupo 5 de retos de cryptopals: https://cryptopals.com/sets/5/challenges/33.

Tamaño de clave con el p del NIST: 1024 bits.

Autor: Daysapro.
'''


from Crypto.Util.number import getPrime
from secrets import randbelow


def generate_safe_prime(n):
    return getPrime(n)


def generate_private_key(n):
    return randbelow(2**n)


def generate_public_key(private_key, g, p):
    return pow(g, private_key, p)


def generate_shared_key(private_key, public_key, p):
    return pow(public_key, private_key, p)


def main():
    # p y g dados por el NIST. También se podría generar un primo seguro de n bits usando la función generate_safe_prime
    p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
    p = int(p, 16)

    g = 2

    a = generate_private_key(1024)
    A = generate_public_key(a, g, p)

    b = generate_private_key(1024)
    B = generate_public_key(b, g, p)

    S = generate_shared_key(a, B, p)

    assert S == generate_shared_key(b, A, p)

    print("La clave compartida es: {S}".format(S=S))


if __name__ == '__main__':
    main()