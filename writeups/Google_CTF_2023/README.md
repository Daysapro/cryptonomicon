# Google CTF 2023

[![follow_tag](https://img.shields.io/github/followers/Daysapro?label=Seguir&style=social)](https://github.com/Daysapro) [![like_tag](https://img.shields.io/github/stars/Daysapro/cryptonomicon?label=Favorito&style=social)](https://github.com/Daysapro/cryptonomicon)

[![ctf_tag](https://img.shields.io/:CTF-2ecc71.svg?labelColor=472D27&color=472D27)]() [![prng_tag](https://img.shields.io/:PRNG-2ecc71.svg?labelColor=008F39&color=008F39)]() [![public_key_tag](https://img.shields.io/:clave%20pública-2ecc71.svg?labelColor=FF0000&color=FF0000)]() [![modular_arithmetic_tag](https://img.shields.io/:aritmética%20modular-2ecc71.svg?labelColor=149AFF&color=149AFF)]()

> **23/06/2023 20:00 CEST - 25/06/2023 20:00 CEST**

Todo el código desarrollado se puede consultar en la carpeta de scripts.


## Least Common Genominator?

> **352/676 soluciones | 50 puntos**

**Enunciado**

    Someone used this program to send me an encrypted message but I can't read it! It uses something called an LCG, do you know what it is? I dumped the first six consecutive values generated from it but what do I do with it?!

**Archivos**

    generate.py

```python
from secret import config
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, isPrime

class LCG:
    lcg_m = config.m
    lcg_c = config.c
    lcg_n = config.n

    def __init__(self, lcg_s):
        self.state = lcg_s

    def next(self):
        self.state = (self.state * self.lcg_m + self.lcg_c) % self.lcg_n
        return self.state

if __name__ == '__main__':

    assert 4096 % config.it == 0
    assert config.it == 8
    assert 4096 % config.bits == 0
    assert config.bits == 512

    # Find prime value of specified bits a specified amount of times
    seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
    lcg = LCG(seed)
    primes_arr = []
    
    dump = True
    items = 0
    dump_file = open("dump.txt", "w")

    primes_n = 1
    while True:
        for i in range(config.it):
            while True:
                prime_candidate = lcg.next()
                if dump:
                    dump_file.write(str(prime_candidate) + '\n')
                    items += 1
                    if items == 6:
                        dump = False
                        dump_file.close()
                if not isPrime(prime_candidate):
                    continue
                elif prime_candidate.bit_length() != config.bits:
                    continue
                else:
                    primes_n *= prime_candidate
                    primes_arr.append(prime_candidate)
                    break
        
        # Check bit length
        if primes_n.bit_length() > 4096:
            print("bit length", primes_n.bit_length())
            primes_arr.clear()
            primes_n = 1
            continue
        else:
            break

    # Create public key 'n'
    n = 1
    for j in primes_arr:
        n *= j
    print("[+] Public Key: ", n)
    print("[+] size: ", n.bit_length(), "bits")

    # Calculate totient 'Phi(n)'
    phi = 1
    for k in primes_arr:
        phi *= (k - 1)

    # Calculate private key 'd'
    d = pow(config.e, -1, phi)

    # Generate Flag
    assert config.flag.startswith(b"CTF{")
    assert config.flag.endswith(b"}")
    enc_flag = bytes_to_long(config.flag)
    assert enc_flag < n

    # Encrypt Flag
    _enc = pow(enc_flag, config.e, n)

    with open ("flag.txt", "wb") as flag_file:
        flag_file.write(_enc.to_bytes(n.bit_length(), "little"))

    # Export RSA Key
    rsa = RSA.construct((n, config.e))
    with open ("public.pem", "w") as pub_file:
        pub_file.write(rsa.exportKey().decode())
```

    dump.txt

```python
2166771675595184069339107365908377157701164485820981409993925279512199123418374034275465590004848135946671454084220731645099286746251308323653144363063385
6729272950467625456298454678219613090467254824679318993052294587570153424935267364971827277137521929202783621553421958533761123653824135472378133765236115
2230396903302352921484704122705539403201050490164649102182798059926343096511158288867301614648471516723052092761312105117735046752506523136197227936190287
4578847787736143756850823407168519112175260092601476810539830792656568747136604250146858111418705054138266193348169239751046779010474924367072989895377792
7578332979479086546637469036948482551151240099803812235949997147892871097982293017256475189504447955147399405791875395450814297264039908361472603256921612
2550420443270381003007873520763042837493244197616666667768397146110589301602119884836605418664463550865399026934848289084292975494312467018767881691302197
```

    public.pem

```python
-----BEGIN PUBLIC KEY-----
MIICITANBgkqhkiG9w0BAQEFAAOCAg4AMIICCQKCAgACnR8r4GemZPmX2+zLsBgz
qHanMd0pbEGFRRldNezYX9A3HT99peociEbEMUnUaVWuDbzHJX7drG8s/exQW4XF
fE5lGy+D0gSkJfQS1komUxic6iWH/1bZnU6rWFJlpbIzy/3IMx4QIx5cbOA0SsLu
AomMEi4ZERGLxm2ta7ZZZuEYVYIa9/mrlXYkTgi1fxLguT35ykHNk5Rm8e8Q8KF/
V2pQ3CQIQYZra2WLGNsxOXW7FLttmMyzgi4WQjLE/SVMs7Th5lGkjmXoQpMcc0Zh
kL3H0vMHWtQeclqsE+QXgAUQFshiSb0auf69y/H+R+qJCO0jRgBz3OVudSx91oSB
GaF7DTfFu3LsgJvMDRAdhPgdlLLzlR0PldVq1jKwjs1dWce2R5r4B0dnXqPrxLuu
A/WNp3ni3jp6AL2y7MKn2AylPUEr+/fQ6+B33wuIHcZiXHdYYPvemehtCf1WCV4Q
/C10Q3E6PK6R+dncE7ZUg0U3qnA84rAZUwweGLUD2yXngHMxDLLRv44Uv28XFvl3
5kFrlJhIhxtx/Fon70EKNboDCT8UXJ5ZlMyt47WBmYGp7FZbafbH6coLAQr1LQCy
HCJYimu7lXr9eGYixE93xXHJ3KIJPaZGmhW3qbj3B8ZxrIvGjkZtHqiw+OCNj343
Q44DknQ8F3CwBmZUmBxZSQIDAQAB
-----END PUBLIC KEY-----
```

    flag.txt

```python
Fichero cifrado.
```


### Resolución

[LCG (Linear Congruential Generator)](https://en.wikipedia.org/wiki/Linear_congruential_generator) es un algoritmo que permite la creación de una secuencia de números pseudoaleatorios. Es uno de los generadores de números pseudoaleatorios más conocidos y utiliza operaciones de aritmética modular para conseguir la aleatoriedad.

La secuencia de valores se calcula según:

$$X_{i + 1} \equiv (m \cdot X_i + c) \bmod n$$

Donde $X_0$ es el valor inicial o semilla.

En este ejercicio, se conoce la semilla y los primeros seis valores generados. El sistema continúa generando valores aleatorios a partir de los dados, verifica si son primos y si tienen una longitud en bits determinada para, si cumplen las condiciones, calcular un módulo $n$ para cifrar en RSA. Este módulo $n$ está compuesto por el producto de ocho números primos de 512 bits, lo cual hace imposible su factorización en un tiempo razonable.

El código proporcionado no requiere de muchos recursos computacionales para ser ejecutado. Es decir, si se recuperan los parámetros $m$, $c$ y $n$ del generador de números aleatorios, se podría ejecutar la búsqueda de los primos sin problemas. 

Tenemos:

$$s_1 \equiv (m \cdot seed + c) \bmod n$$

$$s_2 \equiv (m \cdot s_1 + c) \bmod n$$

$$s_3 \equiv (m \cdot s_2 + c) \bmod n$$

$$s_4 \equiv (m \cdot s_3 + c) \bmod n$$

$$s_5 \equiv (m \cdot s_4 + c) \bmod n$$

$$s_6 \equiv (m \cdot s_5 + c) \bmod n$$

Aunque tenemos tres ecuaciones con tres incógnitas, este sistema no se puede resolver directamente debido a que el módulo es desconocido. Sin embargo, se puede usar un truco basado en teoría de números y propiedades aritméticas para avanzar.

Restando cada ecuación con su anterior, se obtiene que:

$$s_2 - s_1 \equiv (s_1 - seed) \cdot m \bmod n$$

$$s_3 - s_2 \equiv (s_2 - s_1) \cdot m \bmod n$$

$$s_4 - s_3 \equiv (s_3 - s_2) \cdot m \bmod n$$

$$s_5 - s_4 \equiv (s_4 - s_3) \cdot m \bmod n$$

$$s_6 - s_5 \equiv (s_5 - s_4) \cdot m \bmod n$$

Despejando $m$:

$$m \equiv (s_2 - s_1) \cdot (s_1 - seed)^{-1}\bmod n$$

$$m \equiv (s_3 - s_2) \cdot (s_2 - s_1)^{-1}\bmod n$$

$$m \equiv (s_4 - s_3) \cdot (s_3 - s_2)^{-1}\bmod n$$

$$m \equiv (s_5 - s_4) \cdot (s_4 - s_3)^{-1}\bmod n$$

$$m \equiv (s_6 - s_5) \cdot (s_5 - s_4)^{-1}\bmod n$$

Igualando la primera ecuación con la segunda:

$$(s_2 - s_1) \cdot (s_1 - seed)^{-1} \equiv (s_3 - s_2) \cdot (s_2 - s_1)^{-1}\bmod n$$

$$(s_2 - s_1)^2 \equiv (s_3 - s_2) \cdot (s_1 - seed) \bmod n$$

$$(s_2 - s_1)^2 - (s_3 - s_2) \cdot (s_1 - seed) \equiv 0 \bmod n$$

Así sabemos que $(s_2 - s_1)^2 - (s_3 - s_2) \cdot (s_1 - seed)$ es divisible por $n$. Igualando todas las ecuaciones con $m$ despejada, se pueden obtener diez valores divisibles. Y aquí es donde se sabe que, teniendo distintos múltiplos de $n$, es muy probable que el máximo común divisor sea $n$. Así se obtiene uno de los parámetros desconocidos.

Conociendo $n$:

$$m \equiv (s_2 - s_1) \cdot (s_1 - seed)^{-1}\bmod n$$

Y con $m$:

$$s_1 \equiv (m \cdot seed + c) \bmod n$$

$$c \equiv s_1 - m \cdot seed \bmod n$$

Conocidos los tres parámetros se ejecuta la generación de primos.

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import GCD
from Crypto.Util.number import isPrime, long_to_bytes


with open("public.pem", "r") as archivo:
    pem = archivo.read()

public_key = RSA.importKey(pem)

n = public_key.n
e = public_key.e

it = 8
bits = 512

seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
s1 = 2166771675595184069339107365908377157701164485820981409993925279512199123418374034275465590004848135946671454084220731645099286746251308323653144363063385
s2 = 6729272950467625456298454678219613090467254824679318993052294587570153424935267364971827277137521929202783621553421958533761123653824135472378133765236115
s3 = 2230396903302352921484704122705539403201050490164649102182798059926343096511158288867301614648471516723052092761312105117735046752506523136197227936190287
s4 = 4578847787736143756850823407168519112175260092601476810539830792656568747136604250146858111418705054138266193348169239751046779010474924367072989895377792
s5 = 7578332979479086546637469036948482551151240099803812235949997147892871097982293017256475189504447955147399405791875395450814297264039908361472603256921612
s6 = 2550420443270381003007873520763042837493244197616666667768397146110589301602119884836605418664463550865399026934848289084292975494312467018767881691302197

t0 = s1 - seed
t1 = s2 - s1
t2 = s3 - s2
t3 = s4 - s3
t4 = s5 - s4
t5 = s6 - s5

multiple1 = (t0 * t2) - pow(t1, 2)
multiple2 = (t1 * t3) - pow(t2, 2)
multiple3 = (t2 * t4) - pow(t3, 2)
multiple4 = (t3 * t5) - pow(t4, 2)
multiple5 = (t3 * t0) - (t1 * t2)
multiple6 = (t4 * t0) - (t1 * t3)
multiple7 = (t5 * t0) - (t1 * t4)
multiple8 = (t4 * t1) - (t2 * t3)
multiple9 = (t5 * t1) - (t2 * t4)
multiple10 = (t5 * t2) - (t3 * t4)

n2 = GCD(multiple1, multiple2, multiple3, multiple4, multiple5, multiple6, multiple7, multiple8, multiple9, multiple10)

m = (s2 - s1) * pow(s1 - seed, -1, n2) % n2

c = s1 - seed*m % n2

assert s1 == (seed * m + c) % n2


class LCG:
    lcg_m = m
    lcg_c = c
    lcg_n = n2

    def __init__(self, lcg_s):
        self.state = lcg_s

    def next(self):
        self.state = (self.state * self.lcg_m + self.lcg_c) % self.lcg_n
        return self.state


lcg = LCG(seed)

primes_arr = []
primes_n = 1
while True:
    for i in range(it):
        while True:
            prime_candidate = lcg.next()
            if not isPrime(prime_candidate):
                continue
            elif prime_candidate.bit_length() != bits:
                continue
            else:
                primes_n *= prime_candidate
                primes_arr.append(prime_candidate)
                break
    if primes_n.bit_length() > 4096:
        print("bit length", primes_n.bit_length())
        primes_arr.clear()
        primes_n = 1
        continue
    else:
        break

phi = 1
for k in primes_arr:
    phi *= (k - 1)

t3 = pow(e, -1, phi)

with open("flag.txt", "rb") as flag_file:
    flag = flag_file.read()

ciphertext = int.from_bytes(flag, "little")

flag = pow(ciphertext, t3, n)

print(long_to_bytes(flag))
```

> **flag: CTF{C0nGr@tz_RiV35t_5h4MiR_nD_Ad13MaN_W0ulD_b_h@pPy}**