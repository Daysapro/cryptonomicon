# ImaginaryCTF 2023

[![follow_tag](https://img.shields.io/github/followers/Daysapro?label=Seguir&style=social)](https://github.com/Daysapro) [![like_tag](https://img.shields.io/github/stars/Daysapro/cryptonomicon?label=Favorito&style=social)](https://github.com/Daysapro/cryptonomicon)

[![ctf_tag](https://img.shields.io/:CTF-2ecc71.svg?labelColor=472D27&color=472D27)]() [![codification_tag](https://img.shields.io/:codificación-2ecc71.svg?labelColor=FF8000&color=FF8000)]() [![public_key_tag](https://img.shields.io/:clave%20pública-2ecc71.svg?labelColor=FF0000&color=FF0000)]() [![modular_arithmetic_tag](https://img.shields.io/:aritmética%20modular-2ecc71.svg?labelColor=149AFF&color=149AFF)]()

> **21/07/2023 21:00 CEST - 23/07/2023 21:00 CEST** 

Todo el código desarrollado se puede consultar en la carpeta de scripts.


## rsa

> **262/880 soluciones | 100 puntos**

**Enunciado**
    
    I think I did my RSA right...

**Archivos**

    public.pem

```python
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJTzEROqf1384i18XiqfglU1Vu
CqQJaqhmiMGA3zNHLBojFklLfe3cxDwdJMolmbdL//qUc0y9yGYSbLUURleS8VMC
bWkhtI1SCCxAxkqbRSgWIeScd8+ed4JOUXfwTX2nCgO1Pxp1XbeDqba4nnR/agb1
d6/4ciyo6w5bz0OcIwIDAQAB
-----END PUBLIC KEY-----
```

    private.pem

```python
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDJTzEROqf1384i18XiqfglU1VuCqQJaqhmiMGA3zNHLBojFklL
fe3cxDwdJMolmbdL//qUc0y9yGYSbLUURleS8VMCbWkhtI1SCCxAxkqbRSgWIeSc
d8+ed4JOUXfwTX2nCgO1Pxp1XbeDqba4nnR/agb1d6/4ciyo6w5bz0OcIwIDAQAB
AoGAOw2hDjXPuZ/an3v+j7xej8x/XhV/A0gneFSbtwtCxpkYXbyW6a9aTI3AOKhn
KFqMW54Oyud71pxn3PXItNbhrzJLgNhEYrz4N423gDxM7HgqeYogi6XTc0qVh8rB
fnb7s8JB5bGCLKs5tz2zQ99IYHhjQ8LXeMCwbvSaKSLqQqkCQQD+r7yXzewBv1r+
ir4oAtj07iF8Y3QMiHxykgQxEI6ZPcbzz+7WpBgwQ1z6nMCNJuAfs9/Fxt+DpIjo
3z2JdittAkEAylj7In1hwaA3s3L1SPME5GTqvqTcbtvKhPlrWJ7Ci4N/VU+zByM0
BpsYHFo5cRvFOxFlHDIZ4APLn+Wrs2obzwJADWBJdWeZR5Y3PzsmNY/AuUxwccn/
ZFEeyB2nHrSR6LZ35oI7NwazRoWjMn5dFoy+JKwbypVhU9amYiSnZLrSGQJAOxCC
Le0fbd+Qosb5plOZp/l1NDT3SzzI/su3c+TTsNmvf32GKp0yAIOhJBWKEuQiTD2l
n/dX6jXxaDkoR3S/rQJAd+rO4KvBwxurYGGYpN0vGHSJPPmVLyNxPRmyFYcC5CU/
5Z3FWqN+4eFPtujWig2gfkZ/SL3QuB3s5BG0dWN0gA==
-----END RSA PRIVATE KEY-----
```

    flag.enc

```python
Fichero cifrado.
```


### Resolución

Nos proporcionan una clave pública y una clave privada de un sistema RSA, junto con un mensaje encriptado. La clave privada permite descifrar el mensaje según:

$$m \equiv c^d \bmod n$$

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes


with open("flag.enc", 'rb') as flag:
    flag_text = flag.read()
    
private_key = RSA.importKey(open("private.pem", "r").read())
public_key = RSA.importKey(open("public.pem", "r").read())

n = public_key.n
d = private_key.d

print(long_to_bytes(pow(bytes_to_long(flag_text), d, n)))
```

> **flag: ictf{keep_your_private_keys_private}**


## emoticons

> **152/880 soluciones | 100 puntos**

**Enunciado**
    
    It seems that emoji "crypto" challenges are all the rage nowadays... Well, here's another one for you!

**Archivos**

    gen.py

```python
import random

emojis = [n for n in "🌸🍔🐳🚀🌞🎉🍦🎈🐶🍕🌺🎸⚡️🦋🌼🎁"]
m = open("text.txt", "rb").read().hex()

random.shuffle(emojis)

for e, c in zip(emojis, "0123456789abcdef"):
  m = m.replace(c, e)

open("out.txt", "w").write(m)
```

    out.txt

```python
🎉🌼🎈🍔🎈🌺🍕🎉🎈🐳🎈🌸🎈🌺🎈⚡🍕🌸🎁🚀🎁🐶🎈🦋🎈🚀🍕🌸🎈🌺🎁🐶🎈🎸🎈⚡🎈🌺🍕🍕🎈⚡🎁🐶🎈🦋🍕🌸🎁🐶🍕🌸🎈🍔🎈🐳🎈🚀🎈🌼🍕🐳🍕🌸🎁🚀🎁🐶🎈🦋🍕🎁🎈🌼🎁🐶🎈🍕🍕🎁🎈🦋🍕🐶🎈🌞🎈🐳🎈🌸🎈🦋🎈🚀🎁🐶🍕🎁🎈🌼🍕🐶🍕🎁🎈🌼🍕🌸🎈🌼🎈⚡🍕🎉🎈🦋🍕🎉🎈🐳🎈🌺🎈⚡🍕🌸🎁🐶🎈🌺🎈🎈🎁🐶🎈🎈🎈🦋🎈🌸🎈🐳🎈🦋🎈🚀🎁🐶🎈🌼🍕🌞🍕🐶🍕🎁🎈🌼🍕🌸🍕🌸🎈🐳🎈🌺🎈⚡🍕🌸🎁🐶🍕🌼🍕🌸🎈🌼🎈🎉🎁🐶🍕🎉🎈🌺🎁🐶🎈🌸🎈🌺🎈⚡🍕🎈🎈🌼🍕🐳🎁🐶🎈🌼🎈🍔🎈🌺🍕🎉🎈🐳🎈🌺🎈⚡🍕🌸🎁🐶🎈🌺🍕🎁🎁🐶🍕🎉🎈🌺🎈⚡🎈🌼🎁🐶🎈🐳🎈⚡🎁🐶🍕🍕🍕🎁🎈🐳🍕🎉🍕🎉🎈🌼🎈⚡🎁🐶🎈🌸🎈🌺🎈🍔🎈🍔🍕🌼🎈⚡🎈🐳🎈🌸🎈🦋🍕🎉🎈🐳🎈🌺🎈⚡🎁⚡🎁🐶🌼🎉🎈🌞🎈🌼🍕🐳🎁🐶🎈🌞🎈🦋🍕🎈🎈🌼🎁🐶🎈🎁🎈🌼🎈🌸🎈🌺🎈🍔🎈🌼🎁🐶🎈🦋🎈⚡🎁🐶🎈🐳🎈⚡🍕🎉🎈🌼🎈🍕🍕🎁🎈🦋🎈🚀🎁🐶🍕🐶🎈🦋🍕🎁🍕🎉🎁🐶🎈🌺🎈🎈🎁🐶🎈🌺🎈⚡🎈🚀🎈🐳🎈⚡🎈🌼🎁🐶🎈🍔🎈🌼🍕🌸🍕🌸🎈🦋🎈🍕🎈🐳🎈⚡🎈🍕🎁🚀🎁🐶🍕🌸🎈🌺🎈🌸🎈🐳🎈🦋🎈🚀🎁🐶🎈🍔🎈🌼🎈🎉🎈🐳🎈🦋🎁🐶🍕🐶🎈🚀🎈🦋🍕🎉🎈🎈🎈🌺🍕🎁🎈🍔🍕🌸🎁🚀🎁🐶🎈🦋🎈⚡🎈🎉🎁🐶🎈🌼🎈🍔🎈🦋🎈🐳🎈🚀🎁🐶🎈🌸🎈🌺🍕🎁🍕🎁🎈...
```


### Resolución

En este ejercicio se realiza una conversión de un texto a su representación hexadecimal y se sustituye cada carácter por un emoticono diferente. El objetivo es realizar un [análisis de frecuencias](https://es.wikipedia.org/wiki/An%C3%A1lisis_de_frecuencias) para saber qué emoticono corresponde a cada carácter.

El análisis de frecuencias se llevó a cabo de manera manual, asumiendo que el texto original tenía coherencia y cohesión. La primera conclusión obtenida fue que los carácteres impares en la mayoría de las casos correspondían al dígito hexadecimal 6 o 7. Esto se basó en que las letras minúsculas en hexadecimal van desde 61 hasta 7A. Por lo tanto, se infirió que el globo representaba al 6, carácter más común en ese intervalo.

Por otro lado, el espacio en hexadecimal se representa como 20. Este 20 debe ser fácil de encontrar, porque representa a dos emoticonos no muy comunes que se repiten juntos cada cierto número de caracteres. El único candidato posible es 🎁🐶. El dígito 2 es el regalo y el dígito 0 el perro.

El siguiente objetivo fue identificar palabras de escasa longitud. En inglés la única palabra común de una sola letra es "a" (un). Buscando dos emoticonos espacios se encuentra 🎈🦋, confirmando el globo como 6 y la mariposa como 1.

Lo siguiente fue descubrir las palabras "and", "the" y "are". Con esto, se pudieron leer fragmentos de palabras que permitían estimar los caracteres restantes.

El texto era:

```
Emoticons, also known as smileys, are graphical representations of facial expressions used to convey emotions or tone in written communication. They have become an integral part of online messaging, social media platforms, and email correspondence. Emoticons are formed using a combination of keyboard characters and symbols, allowing users to express their feelings and add nuance to their text-based conversations. ictf{frequency_analysis_is_really_fun_right} The primary purpose of emoticons is to enhance digital communication by bridging the gap between written text and face-to-face interactions. They provide a way to convey emotions, such as happiness, sadness, surprise, or humor, which can be challenging to express solely through words. For example, a simple smiley face :) can denote happiness or friendliness, while a frowning face :( can indicate sadness or disappointment. Emoticons offer a visual shorthand that helps clarify the intended emotional context of a message, reducing the chances of miscommunication or misunderstandings. Moreover, emoticons also contribute to the creation of a more personalized and relatable online environment. By using emoticons, individuals can infuse their written messages with personality, humor, or sarcasm. This adds depth and richness to conversations, making them more engaging and enjoyable. Emoticons serve as a form of nonverbal communication in the digital realm, providing a way to convey subtle cues and emotional nuances that would typically be expressed through facial expressions, gestures, or tone of voice in face-to-face interactions. In summary, emoticons are graphical representations of facial expressions that have revolutionized online communication. They allow individuals to express emotions and add context to their written messages, improving understanding and reducing the risk of miscommunication. By incorporating emoticons into digital conversations, people can infuse their texts with personality and create a more vibrant and relatable online environment.
```

> **flag: ictf{frequency_analysis_is_really_fun_right}**


## signer

> **94/880 soluciones | 100 puntos**

**Enunciado**
    
    My new secure signing service is up! It uses state-of-the-art cryptographically secure hashes and can sign anything! Except, of course, the password.

**Archivos**

    main.py

```python
import textwrap
from binascii import crc32
from Crypto.Util.number import getPrime

p, q = getPrime(1024), getPrime(1024)
n = p*q
e = 65537
d = pow(e, -1, (p-1)*(q-1))

PASSWORD = b"give me the flag!!!"

print("--------------------------------------------------------------")
print("               Welcome to the secure signing app!             ")
print("  I will sign whatever you want, except the secret password.  ")
print("--------------------------------------------------------------")
print()
print("--------------------------------------------------------------")
print("\n".join(textwrap.wrap(f"{n = }", len("-------------------------------------------------------------"))))
print("--------------------------------------------------------------")
print()

while True:
  print("1. Sign")
  print("2. Get flag")
  choice = int(input())

  if choice == 1:
    print("Enter message:")
    message = input().encode()
    # crc32 is secure and has no collisions, but just in case
    if message == PASSWORD or crc32(message) == crc32(PASSWORD):
      print("Stop this trickery!")
      exit()
    print("Signature:", pow(crc32(message), d, n))
  elif choice == 2:
    print("Enter the signature for the password:")
    s = int(input())
    if pow(s, e, n) == crc32(PASSWORD):
      print("You win! The flag is", open("flag.txt").read())
      exit()
    else:
      print("Wrong.")
      exit()
```


### Resolución

Este ejercicio presenta un sistema de firma RSA de la [verificación por redundancia cíclica (CRC32)](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) de los mensajes.


#### Explotación de firmas RSA

La explotación de los sistemas clásicos de firmas RSA es sencilla por las propiedades multiplicativas del sistema RSA. La firma se calcula como:

$$s \equiv m ^ d \bmod n$$

Pues si deseamos obtener la firma $s$ de un valor $m$ que no podemos pasar por el sistema de firma, pero tenemos las firmas $s_1$ y $s_2$ de los factores $m_1$ y $m_2$, se puede calcular:

$$m = m_1 \cdot m_2$$

$$s_1 \equiv m_1 ^ d \bmod n$$

$$s_2 \equiv m_2 ^ d \bmod n$$

$$s = s_1 \cdot s_2$$

Todo ello sin conocer la clave privada $d$ pero con acceso al sistema de firma.


#### CRC32 hace más difícil las cosas

En el caso del ejercicio que nos ocupa no es tan sencillo. Esos valores de $m$ que podemos introducir en el sistema de firma no son simplemente valores numéricos, sino el código que son los códigos de redundancia cíclica de los mismos. Sin embargo, a pesar de que el autor nos indica lo contrario en un comentario en el código, CRC32 tiene colisiones. 

El procedimiento de ataque es el siguiente:

1. Se calcula el CRC32 del valor del cual queremos obtener la firma. En este caso: ```CRC32(b"give me the flag!!!")```.
2. Se factoriza el valor del CRC32 y se obtienen $m_1$ y $m_2$ tal que $CRC = m_1 \cdot m_2$.
3. Se utiliza alguna herramienta para obtener qué cadenas obtendrían como resultado de su CRC32 $m_1$ y $m_2$. Utilizo [crc32.py](https://github.com/theonlypwner/crc32) de ```theonlypwner```. Estas cadenas las llamo $c_1$ y $c_2$.
4. Se envían las cadenas al sistema de firmas ```Sign```, que calculará:

$$s_1 = CRC(c_1) ^ d \bmod n$$

$$s_1 = m_1 ^ d \bmod n$$

$$s_2 = CRC(c_2) ^ d \bmod n$$

$$s_2 = m_2 ^ d \bmod n$$

5. Por último, se calcula $s$ como $s = s_1 \cdot s_2$ y se envía con la función ```Get flag```.

```python
from binascii import crc32
from pwn import *


PASSWORD = b"give me the flag!!!"
crc = crc32(PASSWORD)
m1 = 262857
m2 = 13477
assert crc == m1 * m2

# crc32.py

c1 = b"22p6NE"
c2 = b"2i_pQM"

assert crc32(c1) == m1
assert crc32(c2) == m2

r = remote('signer.chal.imaginaryctf.org',  1337)
r.recvuntil(b"Get flag")
r.sendline(b"1")
r.recvline()
r.recvline()
r.sendline(c1)
s1 = int(r.recvline().decode().strip()[11:])
r.recvline()
r.sendline(b"1")
r.recvline()
r.recvline()
r.sendline(c2)
s2 = int(r.recvline().decode().strip()[11:])
r.recvline()
r.recvline()

s = s1 * s2

r.sendline(b"2")
r.recvline()
r.sendline(str(s).encode())
print(r.recvline())
```

> **flag: ictf{m4ybe_crc32_wasnt_that_secure_after_all_1ab93213}**