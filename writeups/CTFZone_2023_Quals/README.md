# CTFZone 2023 Quals

[![follow_tag](https://img.shields.io/github/followers/Daysapro?label=Seguir&style=social)](https://github.com/Daysapro) [![like_tag](https://img.shields.io/github/stars/Daysapro/cryptonomicon?label=Favorito&style=social)](https://github.com/Daysapro/cryptonomicon)

[![ctf_tag](https://img.shields.io/:CTF-2ecc71.svg?labelColor=472D27&color=472D27)]() [![prng_tag](https://img.shields.io/:PRNG-2ecc71.svg?labelColor=008F39&color=008F39)]() [![public_key_tag](https://img.shields.io/:clave%20pública-2ecc71.svg?labelColor=FF0000&color=FF0000)]() [![modular_arithmetic_tag](https://img.shields.io/:aritmética%20modular-2ecc71.svg?labelColor=149AFF&color=149AFF)]()

> **12/08/2023 11:00 CEST - 13/08/2023 23:00 CEST**

Todo el código desarrollado se puede consultar en la carpeta de scripts.


## Come on feel the nonce

> **45/1341 soluciones | 194 puntos**

**Enunciado**

    Yet another cryptography task. Decrypt the flag!

**Archivos**

    main.go

```go
package main

import (
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/rand"
	"os"
)

func randInt64() int64 {
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(err)
	}
	return n.Int64()
}

func encrypt(data, priv []byte) string {
	res := make([]byte, 0)
	st := sha256.Sum256(priv)
	for i, b := range data {
		res = append(res, b^st[i])
	}
	return base64.StdEncoding.EncodeToString(res)
}

func decrypt(enc string, priv []byte) string {
	res := make([]byte, 0)
	data, _ := base64.StdEncoding.DecodeString(enc)
	st := sha256.Sum256(priv)
	for i, b := range data {
		res = append(res, b^st[i])
	}
	return string(res)
}

func main() {
	flag := os.Getenv("FLAG")

	curve := elliptic.P256()
	priv, _, _, err := elliptic.GenerateKey(curve, cryptorand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("enc_flag = %q\n", encrypt([]byte(flag), priv))

	rand.Seed(randInt64())

	for i := int64(0); i < randInt64(); i++ {
		rand.Uint64()
	}

	for i := 0; i <= 607; i++ {
		msg := fmt.Sprintf("msg_%d", i)
		hash := sha256.Sum256([]byte(msg))
		h := new(big.Int).SetBytes(hash[:])

		r, s := Sign(curve, rand.Uint64(), priv, h)

		fmt.Printf("h[%[1]d] = %[2]s\nr[%[1]d] = %[3]s\ns[%[1]d] = %[4]s\n", i, h, r, s)
	}
}

func Sign(curve elliptic.Curve, nonce uint64, priv []byte, h *big.Int) (*big.Int, *big.Int) {
	r := new(big.Int)
	s := new(big.Int)
	d := new(big.Int).SetBytes(priv)
	k := new(big.Int).SetUint64(nonce)

	x, _ := curve.ScalarBaseMult(k.Bytes())
	r.Mod(x, curve.Params().P)

	if r.Sign() == 0 {
		panic("bad nonce")
	}

	s.Mul(r, d)
	s.Mod(s, curve.Params().N)
	s.Add(s, h)
	s.Mod(s, curve.Params().N)
	k.ModInverse(k, curve.Params().N)
	s.Mul(s, k)
	s.Mod(s, curve.Params().N)

	return r, s
}
```

    log.txt

```python
enc_flag = "hOtHc2dafgWuv2nHQDGsoGoF+BmDhy3N0seYgY9kVnw="
h[0] = 106132995759974998927623038931468101728092864039673367661724550078579493516352
r[0] = 18051166252496627800102264022724027258301377836259456556817994423615643066607
s[0] = 92640317177062616510163453417907524626349777891295335142117609371090060820235
h[1] = 7879316208808238663812485364896527134152960535409744690121857898575626153029
r[1] = 115471704120523893976825820273729861954380716558612823937677135779401972000099
s[1] = 88253444681758261894850337672595478098707689792795126664973754773335910861625
...
```


### Resolución

Este ejercicio CTF plantea un sistema de firmas [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) con el que calcula firmas representadas con el par $(r, s)$ de un conjunto conocido de textos $h$.

El objetivo es recuperar la clave privada $d$ y poder así usar la función ```decrypt``` dada.


#### ECDSA

El sistema ECDSA parece estar implementado correctamente. Dado un [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) $k$ generado aleatoriamente, la firma $(r, s)$ es:

$$(x_1, y_1) \equiv k \times G \bmod p \rightarrow r = x_1$$

$$s \equiv (r \cdot d + h) \cdot k^{-1} \bmod n$$

Siendo $G$ el generador de una curva elíptica (en este caso [P-256](https://neuromancer.sk/std/nist/P-256)), $p$ el tamaño del campo finito en el que está contenido la curva, $n$ el orden de la curva, $k$ el nonce y $d$ la clave privada.

La operación $\times$ para calcular $r$ es la [multiplicación de un punto de una curva elíptica](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication).

La única diferencia que presenta respecto a la teoría de ECDSA es el uso del módulo $p$ para generar el valor $r$ en lugar de usar el orden de la curva $n$. Esta implementación es similar al sistema [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm) clásico y no debería cambiar la resolución de este ejercicio.


#### Implementación ```math/rand``` Golang

Tanto el título como el código del ejercicio nos indica que el problema del sistema está relacionado con el nonce. Un nonce es un número que se usa en un sistema criptográfico una única vez. Cualquier reutilización o mala generación del mismo podría comprometer todo el sistema.

En este caso la generación de este elemento es insegura, dadas las características de la implementación de la librería ```math/rand``` de Golang.

```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rand

/*
 * Uniform distribution
 *
 * algorithm by
 * DP Mitchell and JA Reeds
 */

const (
	rngLen   = 607
	rngTap   = 273
	rngMax   = 1 << 63
	rngMask  = rngMax - 1
	int32max = (1 << 31) - 1
)

var (
	// rngCooked used for seeding. See gen_cooked.go for details.
	rngCooked [rngLen]int64 = [...]int64{
		-4181792142133755926, -4576982950128230565, 1395769623340756751, 5333664234075297259,
		-6347679516498800754, 9033628115061424579, 7143218595135194537, 4812947590706362721,
		7937252194349799378, 5307299880338848416, 8209348851763925077, -7107630437535961764,
		...
	}
)

type rngSource struct {
	tap  int           // index into vec
	feed int           // index into vec
	vec  [rngLen]int64 // current feedback register
}

// seed rng x[n+1] = 48271 * x[n] mod (2**31 - 1)
func seedrand(x int32) int32 {
	const (
		A = 48271
		Q = 44488
		R = 3399
	)

	hi := x / Q
	lo := x % Q
	x = A*lo - R*hi
	if x < 0 {
		x += int32max
	}
	return x
}

// Seed uses the provided seed value to initialize the generator to a deterministic state.
func (rng *rngSource) Seed(seed int64) {
	rng.tap = 0
	rng.feed = rngLen - rngTap

	seed = seed % int32max
	if seed < 0 {
		seed += int32max
	}
	if seed == 0 {
		seed = 89482311
	}

	x := int32(seed)
	for i := -20; i < rngLen; i++ {
		x = seedrand(x)
		if i >= 0 {
			var u int64
			u = int64(x) << 40
			x = seedrand(x)
			u ^= int64(x) << 20
			x = seedrand(x)
			u ^= int64(x)
			u ^= rngCooked[i]
			rng.vec[i] = u
		}
	}
}

// Int63 returns a non-negative pseudo-random 63-bit integer as an int64.
func (rng *rngSource) Int63() int64 {
	return int64(rng.Uint64() & rngMask)
}

// Uint64 returns a non-negative pseudo-random 64-bit integer as a uint64.
func (rng *rngSource) Uint64() uint64 {
	rng.tap--
	if rng.tap < 0 {
		rng.tap += rngLen
	}

	rng.feed--
	if rng.feed < 0 {
		rng.feed += rngLen
	}

	x := rng.vec[rng.feed] + rng.vec[rng.tap]
	rng.vec[rng.feed] = x
	return uint64(x)
}	
```

En la función ```Uint64()``` se calcula el número aleatorio $x$, que es igual dos valores del vector $vec$ determinados por los índices $tap$ y $feed$. El valor resultado se introduce en el vector sobreescribiendo un elemento.

El vector $vec$ en la librería original tiene una longitud de 607 elementos, $tap$ se inicia en 0 y $feed$ en 334. $feed$ se encarga de indicar qué elemento de $vec$ sustituir, por lo que empezando por el elemento 334 irá sustituyendo el vector hasta el elemento 0 para continuar con el final del vector.

Dada una lista de elementos generados, el nuevo elemento será la suma del elemento que voy a sustituir indicado por $feed$ (que se habrá generado hace 607 iteraciones, longitud del vector), más el elemento indicado por el desfase de $tap$ y $feed$ (334, porque $tap$ siempre apuntará al elemento 334 por detrás de $feed$).

En este CTF, se generan 608 nonces con este sistema, por lo que el último generado será:

$$k_{607} = k_{0} + k_{334}$$


#### Volviendo al sistema ECDSA

Del sistema de generación de números pseudoaleatorios se ha obtenido una relación entre dos variables. Del sistema de firmas se puede seguir obteniendo información.

Se sabe que:

$$s \equiv (r \cdot d + h) \cdot k^{-1} \bmod n$$

$$s \cdot k \equiv r \cdot d + h \bmod n$$

$$k \equiv (r \cdot d + h) \cdot s^{-1} \bmod n$$

Se puede establecer el siguiente sistema:

$$k_{607} = k_{0} + k_{334}$$

$$k_0 \equiv (r_0 \cdot d + h_0) \cdot s_0^{-1} \bmod n$$

$$k_{334} \equiv (r_{334} \cdot d + h_{334}) \cdot s_{334}^{-1} \bmod n$$

$$k_{607} \equiv (r_{607} \cdot d + h_{607}) \cdot s_{607}^{-1} \bmod n$$

Siendo los nonces $k$ y la clave privada $d$ desconocidas. Es resoluble, se tienen 4 ecuaciones y 4 variables.

$$(r_{607} \cdot d + h_{607}) \cdot s_{607}^{-1} \equiv (r_0 \cdot d + h_0) \cdot s_0^{-1} + (r_{334} \cdot d + h_{334}) \cdot s_{334}^{-1} \bmod n$$

$$r_{607} \cdot d + h_{607} \equiv (r_0 \cdot d + h_0) \cdot s_0^{-1} \cdot s_{607} + (r_{334} \cdot d + h_{334}) \cdot s_{334}^{-1} \cdot s_{607} \bmod n$$

$$r_{607} \cdot d \equiv (r_0 \cdot d + h_0) \cdot s_0^{-1} \cdot s_{607} + (r_{334} \cdot d + h_{334}) \cdot s_{334}^{-1} \cdot s_{607} - h_{607} \bmod n$$

$$d \equiv (r_0 \cdot d + h_0) \cdot s_0^{-1} \cdot s_{607} \cdot r_{607}^{-1} + (r_{334} \cdot d + h_{334}) \cdot s_{334}^{-1} \cdot s_{607} \cdot r_{607}^{-1} - h_{607} \cdot r_{607}^{-1} \bmod n$$

$$d \equiv r_0 \cdot d \cdot s_0^{-1} \cdot s_{607} \cdot r_{607}^{-1} + h_0 \cdot s_0^{-1} \cdot s_{607} \cdot r_{607}^{-1} + r_{334} \cdot d \cdot s_{334}^{-1} \cdot s_{607} \cdot r_{607}^{-1} + h_{334} \cdot s_{334}^{-1} \cdot s_{607} \cdot r_{607}^{-1} - h_{607} \cdot r_{607}^{-1} \bmod n$$

$$d - r_0 \cdot d \cdot s_0^{-1} \cdot s_{607} \cdot r_{607}^{-1} - r_{334} \cdot d \cdot s_{334}^{-1} \cdot s_{607} \cdot r_{607}^{-1} \equiv  h_0 \cdot s_0^{-1} \cdot s_{607} \cdot r_{607}^{-1} + h_{334} \cdot s_{334}^{-1} \cdot s_{607} \cdot r_{607}^{-1} - h_{607} \cdot r_{607}^{-1} \bmod n$$

$$d \cdot (1 - r_0 \cdot s_0^{-1} \cdot s_{607} \cdot r_{607}^{-1} - r_{334} \cdot s_{334}^{-1} \cdot s_{607} \cdot r_{607}^{-1}) \equiv  h_0 \cdot s_0^{-1} \cdot s_{607} \cdot r_{607}^{-1} + h_{334} \cdot s_{334}^{-1} \cdot s_{607} \cdot r_{607}^{-1} - h_{607} \cdot r_{607}^{-1} \bmod n$$

$$d \equiv (h_0 \cdot s_0^{-1} \cdot s_{607} \cdot r_{607}^{-1} + h_{334} \cdot s_{334}^{-1} \cdot s_{607} \cdot r_{607}^{-1} - h_{607} \cdot r_{607}^{-1}) \cdot (1 - r_0 \cdot s_0^{-1} \cdot s_{607} \cdot r_{607}^{-1} - r_{334} \cdot s_{334}^{-1} \cdot s_{607} \cdot r_{607}^{-1})^{-1} \bmod n$$

```python
from Crypto.Util.number import long_to_bytes
from base64 import b64decode
from hashlib import sha256


with open("log.txt", "rb") as file:
    log = file.read().decode().split("\n")

enc_flag = b64decode(log[0].split(" \"")[1][:-1].encode())
log = log[1:-1]

h = []
r = []
s = []

for i in range(len(log) // 3):
    h.append(int(log[i * 3].split("= ")[1]))
    r.append(int(log[i * 3 + 1].split("= ")[1]))
    s.append(int(log[i * 3 + 2].split("= ")[1]))

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

d = (h[0] * pow(s[0], -1, n) * s[607] * pow(r[607], -1, n) + h[334] * pow(s[334], -1, n) * s[607] * pow(r[607], -1, n) - h[607] * pow(r[607], -1, n)) * pow(1 - r[0] * pow(s[0], -1, n) * s[607] * pow(r[607], -1, n) - r[334] * pow(s[334], -1, n) * s[607] * pow(r[607], -1, n), -1, n) % n

hash = sha256()
hash.update(long_to_bytes(d))
key = hash.digest()

flag = ""
for i in range(len(enc_flag)):
    flag += chr(enc_flag[i] ^ key[i])

print(flag)
```

> **flag: ctfzone{r3l4t3d_n0nc3$_4r3_b4d!}**