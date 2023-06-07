# Break the Syntax CTF 2023

[![follow_tag](https://img.shields.io/github/followers/Daysapro?label=Seguir&style=social)](https://github.com/Daysapro) [![like_tag](https://img.shields.io/github/stars/Daysapro/cryptonomicon?label=Favorito&style=social)](https://github.com/Daysapro/cryptonomicon)

[![ctf_tag](https://img.shields.io/:CTF-2ecc71.svg?labelColor=472D27&color=472D27)]() [![public_key_tag](https://img.shields.io/:clave%20pública-2ecc71.svg?labelColor=FF0000&color=FF0000)]() [![modular_arithmetic_tag](https://img.shields.io/:artimética%20modular-2ecc71.svg?labelColor=149AFF&color=149AFF)]()

> **02/06/2023 18:00 CEST - 04/06/2023 12:00 CEST** 

Se explican los dos ejercicios más resueltos de la sección de criptografía.

Todo el código desarrollado se puede consultar en la carpeta de scripts.


## Break PSI

> **26/156 soluciones | 354 puntos**

**Enunciado**
    
    Trick Alice and Bob and get your flag.

    nc crypto-breakpsi.ch.bts.wh.edu.pl 1337

**Archivos**

    2e0f6f7b0a5c6e6e3430484ebbefa819.py

```python
from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes
import random

FLAG = open("flag", "r")

A = []
B = []
Ahash = []
Bhash = []
Ainv = {}
Binv = {}

limit = 32
setSize = 17
reps = 8


def intersection(A, B):
    return [v for v in A if v in B]


def F(x):
    h = SHA256.new(data=long_to_bytes(x))
    return h.digest().hex()


def hash_list(l):
    h = SHA256.new(data=bytes(str(l), "utf-8"))
    return h.digest()


def is_valid(Asi, Bsi):
    if Asi == [] or Bsi == []:
        return 0
    if hash_list(Asi) != hash_list(Bsi):
        return 0

    cnt = {}
    for a in Asi:
        if Ainv[a] in cnt:
            cnt[Ainv[a]] += 1
        else:
            cnt[Ainv[a]] = 1
    for v in cnt.values():
        if v != reps + 1:
            return 0

    cnt = {}
    for b in Bsi:
        if Binv[b] in cnt:
            cnt[Binv[b]] += 1
        else:
            cnt[Binv[b]] = 1
    for v in cnt.values():
        if v != reps + 1:
            return 0

    return 1


for i in range(420):
    A = random.sample(range(limit), setSize)
    B = random.sample(range(limit), setSize)
    Ahash = []
    Bhash = []
    Ainv = {}
    Binv = {}

    for i in range(setSize):
        for j in range(1, reps + 1):
            A.append(A[i] + limit * j)
            B.append(B[i] + limit * j)

    for a in A:
        h = F(a)
        Ahash.append(h)
        Ainv[h] = a % limit

    for b in B:
        h = F(b)
        Bhash.append(h)
        Binv[h] = b % limit

    print("Alice:", Ahash)
    print("Bob:", Bhash)

    Asi = input("Send PSI to Alice: ").split()
    Bsi = input("Send PSI to Bob: ").split()

    if is_valid(Asi, Bsi):
        if intersection(Ahash, Bhash) == Asi and intersection(Ahash, Bhash) == Bsi:
            print("Honesty is not a way to solve this challenge")
            exit()
    else:
        print("Cheater!")
        exit()

print("You got me! Here is your flag:", FLAG.read())
```


### Resolución

[PSI (Private set intersection)](https://en.wikipedia.org/wiki/Private_set_intersection) es un protocolo para buscar la intersección de dos conjuntos de datos sin revelar sus contenidos. En este ejercicio, nosotros actuamos como intermediario en el cálculo de esta intersección. 

Para garantizar la privacidad de los datos, los valores de los conjuntos se transforman mediante una función hash, en este caso SHA256. Nuestro objetivo es superar la función ```is_valid``` sin que la intersección enviada sea igual a la real. Si fuera igual, nos indicaría que ese no es el camino a seguir para resolver el CTF.


#### Generación de los conjuntos

Los conjuntos se generan inicialmente con valores del $0$ al $31$. Luego, se multiplican su tamaño $n$ veces, donde $n$ es un número de repeticiones. En este caso, $n = 8$. Esta fase se le denomina expansión del conjunto.

Se calculan dos conjuntos inversos, $Ainv$ y $Binv$, que almacenan los valores de los conjuntos módulo $32$.

La función ```is_valid``` calcula la validez de nuestro conjunto intersección contando la cantidad de veces que aparecen los valores de $Ainv$ y $Binv$. Dado que durante la expansión se calculan los nuevos valores según $A[i] + 32 \cdot j$ siendo $j$ la iteración de repetición y $A[i]$ los valores iniciales, se sabe que un mismo valor módulo $32$ se repetirá $n$ veces.

Por tanto, como atacantes necesitamos generar un conjunto que no sea igual que la intersección pero que tenga el mismo número de valores originales módulo $32$ que el número de repeticiones $n$. 

La función ```is_valid``` ni siquiera comprueba que los valores de la intersección proporcionada pertenecen a los $A$ y $B$ originales, por lo que se podría generar un conjunto cualquiera con el método de generación de conjuntos del archivo inicial y este validaría el ejercicio consigo mismo.


#### Solución durante la competición

Durante la competición calculé la intersección real cambiando un elemento por su mismo elemento sumado al límite. Así, este nuevo sería $I[i] + 32 \equiv I[i] \bmod 32$, un valor diferente a la intersección real que validaría la función. Esta solución devuelve la flag porque al generarse un número definido de elementos y hacer la operación $A[i] + 32 \cdot j$, a mismo número inicial $A[i]$, mismos elementos derivados. Imaginemos:

$$A = [15, 4, 20, 6]$$

$$B = [7, 15, 6, 2]$$

$$I = [15, 6]$$

Tras la expansión $A[i] + 32 \cdot j$ con $8$ repeticiones:

$$A_{E} = [15, 4, 20, 6, 47, 79, 111, 143, 175, 207, 239, 271, 36, 68, 100, 132, 164, 196, 228, 260, 52, 84, 116, 148, 180, 212, 244, 276, 38, 70, 102, 134, 166, 198, 230, 262]$$

$$B_{E} = [7, 15, 6, 2, 39, 71, 103, 135, 167, 199, 231, 263, 47, 79, 111, 143, 175, 207, 239, 271, 38, 70, 102, 134, 166, 198, 230, 262, 34, 66, 98, 130, 162, 194, 226, 258]$$

$$I_{E} = [15, 6, 47, 79, 111, 143, 175, 207, 239, 271, 38, 70, 102, 134, 166, 198, 230, 262]$$

Los valores que se añaden a la intersección son resultado de $A[i] + 32 \cdot j$ de los elementos de la intersección inicial. En el caso de $A[i] = 15$:

$$j = 1 \rightarrow 15 + 1 \cdot 32 = 47$$

$$j = 2 \rightarrow 15 + 2 \cdot 32 = 79$$

$$j = 3 \rightarrow 15 + 3 \cdot 32 = 111$$

Por lo que todos los valores expandidos de valores que inicialmente formaban parte de la intersección también forman parte de la intersección extendida. Como se generan $n$ elementos expandidos de cada uno, se cumple la condición.

```python
from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes
from pwn import *
from tqdm import tqdm


limit = 32
setSize = 17
reps = 8


def F(x):
    h = SHA256.new(data=long_to_bytes(x))
    return h.digest().hex()


def hash_list(l):
    h = SHA256.new(data=bytes(str(l), "utf-8"))
    return h.digest()


def intersection(A, B):
    return [v for v in A if v in B]


def is_valid(Asi, Bsi):
    if Asi == [] or Bsi == []:
        return 0
    if hash_list(Asi) != hash_list(Bsi):
        return 0

    cnt = {}
    for a in Asi:
        if a_inv[a] in cnt:
            cnt[a_inv[a]] += 1
        else:
            cnt[a_inv[a]] = 1
    for v in cnt.values():
        if v != reps + 1:
            return 0

    cnt = {}
    for b in Bsi:
        if b_inv[b] in cnt:
            cnt[b_inv[b]] += 1
        else:
            cnt[b_inv[b]] = 1
    for v in cnt.values():
        if v != reps + 1:
            return 0
    return 1


def get_hash_dict():
    hash_dict = {}
    for i in range(288):
        hash_dict[F(i)] = i
    return hash_dict


def get_values(hashes):
    values = []
    for hash in hashes:
        values.append(hash_dict[hash])
    return values


def get_inv(values):
    inv = {}
    for value in values:
        h = F(value)
        inv[h] = value % limit
    return inv

r = remote("crypto-breakpsi.ch.bts.wh.edu.pl", 1337)


for i in tqdm(range(420)):
    Alice = eval(r.recvline().strip()[7:].decode('utf-8'))
    Bob = eval(r.recvline().strip()[4:].decode('utf-8'))

    hash_dict = get_hash_dict()
    a_values = get_values(Alice)
    b_values = get_values(Bob)
    a_inv = get_inv(a_values)
    b_inv = get_inv(b_values)

    real_intersection = intersection(Alice, Bob)

    real_intersection[0] = F(hash_dict[real_intersection[0]] + limit)

    assert is_valid(real_intersection, real_intersection)

    str_intersection = ""
    for i in real_intersection:
        str_intersection += i + " "

    r.recvuntil(b": ")
    r.sendline(str_intersection)
    r.recvuntil(b": ")
    r.sendline(str_intersection)

print(r.recvall())
```


#### Solución teórica

La solución anterior, aunque supera la función de validación, no es la mejor. No es necesario realizar cálculos ni llegar a conclusiones tan complejas. Como se ha mencionado anteriormente, un nuevo conjunto generado con sus criterios valida consigo mismo.

```python
limit = 32
setSize = 17
reps = 8

A = random.sample(range(limit), setSize)
Ahash = []
Ainv = {}
Binv = {}

for i in range(setSize):
    for j in range(1, reps + 1):
        A.append(A[i] + limit * j)

for a in A:
    h = F(a)
    Ahash.append(h)
    Ainv[h] = a % limit

Binv = Ainv

print(is_valid(Ahash, Ahash))
```

Se puede comprobar que la salida del código anterior siempre será verdadera.

> **flag: BtSCTF{4lWAys_sHuff1e_PSI_seTs}**


## Textbook

> **5/156 soluciones | 483 puntos**

**Enunciado**
    
    My professor told me that textbook RSA signatures are not secure. Good thing this is not textbook RSA!

    nc crypto-textbook.ch.bts.wh.edu.pl 1337

**Archivos**

    f4254d3801a2b78e272bda65abd9c887.py

```python
from Crypto.Util.number import getPrime, GCD, getRandomRange
from collections import namedtuple


with open('flag', 'r') as f:
    flag = f.read()

public = namedtuple('public', 'n g')
secret = namedtuple('secret', 'n phi mu')
sig = namedtuple('sig', 's1 s2')

b = 1024
p = getPrime(b)
q = getPrime(b)

assert p != q

n = p * q
phi = (p - 1) * (q - 1)
g = n + 1
mu = pow(phi, -1, n)

pk = public(n, g)
sk = secret(n, phi, mu)

# mask for additional security!!!
mask = getRandomRange(2 ** (n.bit_length() * 2 - 2), (2 ** (n.bit_length() * 2 - 1)))

def h(s: bytes) -> int:
    return int.from_bytes(s, 'big', signed=True)

def int_to_bytes(n: int) -> bytes:
    return n.to_bytes(n.bit_length() // 8 + 1, 'big', signed=True)

def encrypt(m: bytes, pk: public) -> bytes:
    n, g = pk
    r = getRandomRange(1, n)
    assert GCD(r, n) == 1
    mh = h(m)
    c = (pow(g, mh, n ** 2) * pow(r, n, n ** 2)) % (n ** 2)

    return pow(c, mask, n ** 2)

def sign(m: bytes, sk: secret) -> sig:
    n, phi, mi = sk
    mh = (h(m) * mask) % (n ** 2)
    d = pow(mh, phi, n ** 2)
    e = (d - 1) // n

    s1 = (e * mi) % n
    n_inv = pow(n, -1, phi)
    s2 = pow(mh * pow(g, -s1, n), n_inv, n)
    
    return sig(s1, s2)

def verify(m: bytes, sig: sig, pk: public) -> bool:
    s1, s2 = sig
    n, g = pk
    mh = (h(m) * mask) % (n ** 2)
    
    m_prim = pow(g, s1, n ** 2) * pow(s2, n, n ** 2) % (n ** 2)
    return m_prim == mh

if __name__=="__main__":
    flag_enc = encrypt(flag.encode(), pk)
    flag_enc = int_to_bytes(flag_enc)
    print("Hello to my signing service ^^\n")
    print("My public key:")
    print("n =", pk.n)
    print("g =", pk.g)
    print("\nHere, have flag. It's encrypted and masked anyways, so who cares.\n")
    print("flag =", (flag_enc.hex()), "\n")


    while True:
        print("What do you want to do?")
        print("[1] Sign something", "[2] Verify signature", "[3] Exit", sep="\n")

        function = input(">")

        if function == "1":
            message = bytes.fromhex(input("Give me something to sign!\n(hex)>"))
            signature = sign(message, sk)
            print(f"s1 = {signature.s1}\ns2 = {signature.s2}")
        if function == "2":
            message = bytes.fromhex(input("Message to verify\n(hex)>"))
            print("Signature:")
            signature = sig(int(input("s1:\n(int)>")), int(input("s2:\n(int)>")))
            if verify(message, signature, pk):
                print("verified!")
            else:
                print("not verified!")
        if function == "3":
            exit()
```


### Resolución

Se presenta un sistema de firmas basado en el [criptosistema Paillier](https://en.wikipedia.org/wiki/Paillier_cryptosystem). Este algoritmo combina las características de la criptografía asimétrica con [propiedades homomórficas](https://en.wikipedia.org/wiki/Homomorphic_encryption).

Específicamente es la variante simplificada en la que $g = n + 1$, $\lambda = \varphi(n)$, $\mu = \varphi(n)^{-1}$ y $\varphi(n) = (p - 1) \cdot (q - 1)$, en la que:

$$c = g^m \cdot r^n \bmod n^2$$

$$m = L(c^\lambda \bmod n^2) \cdot \mu \bmod n$$

$$ L(x) = \frac{x - 1}{n}$$

Se observan paralelismos con el código proporcionado. La función ```encrypt``` es el cifrado y el valor $s_1$ en la función ```sign``` el descifrado.  


#### Recuperando $\mu$, $\varphi$ y $mask$

En las siguientes explicaciones se firman valores arbitrarios de $m$ con intención de obtener información de las variables privadas en base a las firmas $s_1$ y $s_2$.

Se pueden obtener los parámetros privados $\mu$ y $\varphi$ observando el valor de la firma $s_1$. Siendo el mensaje a firmar $m = 0$:

$$ mh \equiv (0 \cdot mask) \bmod n^2 \equiv 0 \bmod n^2$$

$$d \equiv 0^\varphi \bmod n^2 \equiv 0 \bmod n^2$$

$$e = (0 - 1) // n = -1$$

$$s_1 \equiv -1 \cdot \mu \bmod n^2$$

Viendo $s_1$ se puede calcular $\mu$ y $\varphi$ según $\mu \equiv \varphi^{-1} \bmod n$.

Además, si firmamos $m = 1$ y obtenemos $s_1$ y $s_2$, según la función ```verify```:

$$mh \equiv (g^{s_1} \bmod n^2) \cdot ({s_2}^n \bmod n^2) \bmod n^2$$

$$mh \equiv 1 \cdot mask \bmod n^2$$

$$mask \equiv (g^{s_1} \bmod n^2) \cdot ({s_2}^n \bmod n^2) \bmod n^2$$

Ya se han recuperado todas las variables privadas del sistema $\mu$, $\varphi$ y $mask$, en función a las variables conocidas.


#### Propiedades homomórficas

El sistema Paillier tiene unas propiedades homomórficas que le hacen especial frente al resto:

$$D(E(m_1, r_1) \cdot E(m_2, r_2) \bmod n^2) \equiv m_1 + m_2 \bmod n$$

$$D(E(m_1, r_1) \cdot g^{m_2} \bmod n^2) \equiv m_1 + m_2 \bmod n$$

$$D(E(m_1, r_1)^{m_2} \bmod n^2) \equiv m_1 \cdot m_2 \bmod n$$

Según la función ```encrypt```:

$$flagenc \equiv c^{mask} \bmod n^2$$

Se puede desarollar:

$$c = E(flag)$$

$$flagenc \equiv E(flag)^{mask} \bmod n^2$$

Aplicando la tercera propiedad, decodificando $flagenc$ y considerando esa decodificación la flag solo con la máscara:

$$flagmask \equiv D(E(flag)^{mask} \bmod n^2)$$

$$flagmask \equiv flag \cdot mask \bmod n$$

Usando la fórmula de descifrado:

$$flagmask \equiv L(flagenc^\varphi \bmod n^2) \cdot \mu \bmod n$$

$$flag \equiv flagmask \cdot (mask^{-1} \bmod n) \bmod n$$

```python
from Crypto.Util.number import long_to_bytes


n = 21681297669182728074352803263442466828602720333142302446762006692965701217590667073811727774020316753675101387897937957606709604735414772772503037382708861385872320483969852130492098512175180986980539021138682848908549495302818464128432106010638184701774996849671393376895463924808700594336761144020409257869001024705774125138037120854493498205846168091055167537718085782669631600498515013880633422863931918732630368546179505441113203208076467009279895106115068597331057927389872798288089358208231784298821775626006876936567695889100448491196100735610923577273460357520955201454233414599025159271658381501766389770677
g = 21681297669182728074352803263442466828602720333142302446762006692965701217590667073811727774020316753675101387897937957606709604735414772772503037382708861385872320483969852130492098512175180986980539021138682848908549495302818464128432106010638184701774996849671393376895463924808700594336761144020409257869001024705774125138037120854493498205846168091055167537718085782669631600498515013880633422863931918732630368546179505441113203208076467009279895106115068597331057927389872798288089358208231784298821775626006876936567695889100448491196100735610923577273460357520955201454233414599025159271658381501766389770678

flag = 0x0f6afc95ccb6045bd85296b734620f647c273bc6f88dcc25a3bc19e98d051d24041667378e587507d063dd1f0cdde10f412ffb0b56f53284d7d50dcbd94669dbb0d697746fb7a35c8bbe69f68018170de9b54367b95d2270f0b66f6ef77ad7dcc27b90f8aabd0c7b33830343e471d4c59c86f903b664f80d9a5776b19b7f0c65eae6316d51ca0918c5e8319e676f08f3aa4cb7e45166d4c1d30f77ea2edafe9e2fd04b8e7f915ccb6d97d409f742a77c83e6d7b0d488c711841acfc8df706bccba67997adc0a00e5dd96dffb0aaeef87d8fd272dc7b4f82beb8445bd52b1c33990ccd187c45370eafa6560b9bbdece5357313e1e5f275f4b146f200149c44a02e1d36582732daad6d20368a3b8f1e8f7162ed07fbef82b1512788537ca720fb28664b4dac805c877e3e2d64947b2aa61dc303bcd767a2d79da86212642b9de4cebfa4991d9b48f1b090545c3355a740a2d7beb2e0800bc8ebd64f897cd07e42a51059af62fa62d3217407206b424a73e82c0e0a42f1c2ca6716e48c2a8ae8ac2e1a597551f0a6c1762d47d4628c19ae994b0bb754ed6aa1f1c5486b86aa707219dbf827218f5855c41b06e9574d74fc84a70cf1a307762a0df408391495f58babbd2048545285674863ff985056ea5c2b005c9b3e2e07cd705d203359d3e332a846b32c46c5299b822b600ebb3969cb3a236ed6be00fa2f450d5bbb5ade03277

s1_0 = 7124063827524244118567987067718200588118631179272635179021550445094081342568875079774966517588135523364642210818374936874888431770937145319516078247139467258531884622754353539073431767312811359113105521766221552258564245775415327836214781661988679445473371235496836147561417643009875924294666666769701435204009565466687566702716588245922755692558521209143552254004235520407019517079460812551593944598707910054436113454438098298911803287371345214489931906207690687762727625788008587612936371588162225336856660010824297642274537433017078808909431220189272096617405035795150567820104078942118616069008786800734894935244

mu = (s1_0 * pow(-1, -1, n)) % n
phi = pow(mu, -1, n)

assert mu == pow(phi, -1, n)

s1_1 = 10970285536757575596696601711808122806523347157610550373362820875708067899166902698336511312508786486903758467178289675589842196814921974487446949659354238384519573663192058888884948284846965440619972122353811765867002741596354790188286919706218568164342970625378589162110708666880661791149586601725116513975785228649313675871173785430568108443803910278385312951934305340980779108989011050532625607986726433227604729421067863001363681151098553398199294124467096385797166700520347516937461108978220704318785598283754193103334261303321830662665877096855975502855123261323347604565936257393284638441086651262431904485856

s2_1 = 10248445072082616119370788922624159925693428580134286060558143410646737733472218250230605853764264841611284111948779060558054497051693586126835539302184934941178173019031648629468916643217561983545051998965655023147560771173707151167980865132505419457838780431633138154037798054142434100230883949424403963585983791678148146965486329134294912821608479431201037790430653853725302715131433068873747895900059405649428552016297897333683143498503902660240149644805281845008438910200404218282831907845832802843165825688761110986992118592931856918058966261782739286360638167822066605752169535620848793697570548472776090539525

mask = pow(g, s1_1, n ** 2) * pow(s2_1, n, n ** 2) % (n ** 2)

L = (pow(flag, phi, n**2) - 1) // n
u = pow(phi, -1, n)

flagmask = (L * u) % n

flag = (flagmask * pow(mask, -1, n)) % n

print(long_to_bytes(flag))
```

> **flag: BtSCTF{wh4t_d0_y0u_m34n_1ts_h0m0m0rph1c}**