# Akasec CTF 2024

[![follow_tag](https://img.shields.io/github/followers/Daysapro?label=Seguir&style=social)](https://github.com/Daysapro) [![like_tag](https://img.shields.io/github/stars/Daysapro/cryptonomicon?label=Favorito&style=social)](https://github.com/Daysapro/cryptonomicon)

[![ctf_tag](https://img.shields.io/:CTF-2ecc71.svg?labelColor=472D27&color=472D27)]() [![prng_tag](https://img.shields.io/:PRNG-2ecc71.svg?labelColor=008F39&color=008F39)]() [![public_key_tag](https://img.shields.io/:clave%20pública-2ecc71.svg?labelColor=FF0000&color=FF0000)]() [![modular_arithmetic_tag](https://img.shields.io/:aritmética%20modular-2ecc71.svg?labelColor=149AFF&color=149AFF)]()

> **07/06/2024 15:37 CEST - 09/06/2024 15:37 CEST**

Todo el código desarrollado se puede consultar en la carpeta de scripts.


## GCL

> **45/699 soluciones | 191 puntos**

**Enunciado**

    All about THEORIC and some LUCK

**Archivos**

    chall.py

```python
from random import getrandbits
from Crypto.Util.number import getPrime
from SECRET import FLAG

BITS = 128
m = getPrime(BITS)
s = getrandbits(BITS - 1)
a = getrandbits(BITS - 1)
b = getrandbits(BITS - 1)

def lcg(s, c):
    return c*(a*s + b) % m

if __name__ == "__main__":
    c = []
    r = s
    for i in FLAG:
        r = lcg(r, ord(i))
        c.append(r)
    print("m = {}\nc = {}".format(m, c))
```

    enc.txt

```python
m = 188386979036435484879965008114174264991
c = [139973581469094519216727575374900351861, 72611500524424820710132508411012420565, 140250284171774823110472025667980956543, 32777758636601391326104783245836052689, 93866424818360655182957373584240082579, 171863599957625964609271128026424910780, 79519361871833866309751703823833758895, 157560014678333843523667019607330519198, 124975940725420603096426178838171348774, 3564693226938115115868719960412136082, 171740395033004244209129576880703758137, 92351702560499873288607191820522016910, 150094682983991168941275074808189562445, 85216665671310516224623100332845098274, 16595528649897543867800038656511154165, 19125026372283368463438507438570762609, 176795229245184227193627490600890111381, 12405536363393343486876802251851443164, 21411546298976790262184367895329536928, 182888536880153351183725282563493758721, 138117470020493616013148815568927291737, 32287599436436170232396368906599005001, 163785640221676961026807618948041121515, 73960913430365454320029097511676942987, 15454719718422589834477927328058381231, 187548967342452768771256903662911504220, 159561161576243464490176365717896800999, 68751190791869748062871941359673493536, 121231243784105483671509398006895458898, 14881767206744163076100305953646446453, 175267890044871169868897060667629218625, 147751087332703693307658387948934053643, 144192171120888146499506968416035431150]
```


### Resolución

[LCG (Linear Congruential Generator)](https://en.wikipedia.org/wiki/Linear_congruential_generator) es un algoritmo que permite la creación de una secuencia de números pseudoaleatorios. Es uno de los generadores de números pseudoaleatorios más conocidos y utiliza operaciones de aritmética modular para conseguir la aleatoriedad.

La secuencia de valores se calcula según:

$$X_i \equiv (m \cdot X_{i - 1} + c) \bmod n$$

Donde $X_0$ es el valor inicial o semilla y $m$, $c$ y $n$ coeficientes llamados multiplicador, incremento y módulo respectivamente.

En este ejercicio se nos presenta este algoritmo con una pequeña modificación. La generación de los estados sigue la siguiente ecuación:

$$X_i \equiv f_i \cdot (m \cdot X_{i - 1} + c) \bmod n$$

Siendo $f_i$ los caracteres de la flag.

Se conoce el módulo del generador y todos los estados generados, por lo que mediante el prefijo de la flag se pueden recuperar los coeficientes desconocidos.

Partiendo de:

$$X_1 \equiv f_1 \cdot (m \cdot X_0 + c) \bmod n$$

$$X_1 \cdot f_1^{-1} \equiv (m \cdot X_0 + c) \bmod n$$

$$c \equiv (X_1 \cdot f_1^{-1} - m \cdot X_0) \bmod n$$

Realizando las mismas operaciones con la generación del segundo estado:

$$c \equiv (X_2 \cdot f_2^{-1} - m \cdot X_1) \bmod n$$

$$X_1 \cdot f_1^{-1} - m \cdot X_0 \equiv (X_2 \cdot f_2^{-1} - m \cdot X_1) \bmod n$$

$$m \cdot X_1 - m \cdot X_0 \equiv (X_2 \cdot f_2^{-1} - X_1 \cdot f_1^{-1}) \bmod n$$

$$m \cdot (X_1 - X_0) \equiv (X_2 \cdot f_2^{-1} - X_1 \cdot f_1^{-1}) \bmod n$$

$$m \equiv (X_2 \cdot f_2^{-1} - X_1 \cdot f_1^{-1}) \cdot (X_1 - X_0)^{-1} \bmod n$$

Sabiendo los valores de $X_i$ y con los valores de $f_0$ a $f_6$ ```AKASEC{``` se recupera el multiplicador $m$. Con la ecuación de partida se recupera también el incremento $c$:

$$c \equiv (X_2 \cdot f_2^{-1} - m \cdot X_1) \bmod n$$

Una vez obtenidos los coeficientes solo queda recuperar la flag completa:

$$X_{i + 1} \equiv f_i \cdot (m \cdot X_i + c) \bmod n$$

$$f_i  \equiv X_i \cdot (m \cdot X_{i - 1} + c)^{-1} \bmod n$$

```python
r = [139973581469094519216727575374900351861, 72611500524424820710132508411012420565, 140250284171774823110472025667980956543, 32777758636601391326104783245836052689, 93866424818360655182957373584240082579, 171863599957625964609271128026424910780, 79519361871833866309751703823833758895, 157560014678333843523667019607330519198, 124975940725420603096426178838171348774, 3564693226938115115868719960412136082, 171740395033004244209129576880703758137, 92351702560499873288607191820522016910, 150094682983991168941275074808189562445, 85216665671310516224623100332845098274, 16595528649897543867800038656511154165, 19125026372283368463438507438570762609, 176795229245184227193627490600890111381, 12405536363393343486876802251851443164, 21411546298976790262184367895329536928, 182888536880153351183725282563493758721, 138117470020493616013148815568927291737, 32287599436436170232396368906599005001, 163785640221676961026807618948041121515, 73960913430365454320029097511676942987, 15454719718422589834477927328058381231, 187548967342452768771256903662911504220, 159561161576243464490176365717896800999, 68751190791869748062871941359673493536, 121231243784105483671509398006895458898, 14881767206744163076100305953646446453, 175267890044871169868897060667629218625, 147751087332703693307658387948934053643, 144192171120888146499506968416035431150]

m = 188386979036435484879965008114174264991

c = b"AKASEC{"

a = ((r[2] * pow(c[2], -1, m)) - (r[1] * pow(c[1], -1, m))) * pow(r[1] - r[0], -1, m) % m
b = (r[1] * pow(c[1], -1, m) - a * r[0]) % m

flag = ""
for i in range(1, len(r)):
    flag += chr(r[i] * pow(a*r[i - 1] + b, -1, m) % m)

print("A" + flag)
```

> **flag: AKASEC{++see_?!_just_some_math--}**