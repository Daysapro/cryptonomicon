# Modos de operación de cifrado de bloques

[![follow_tag](https://img.shields.io/github/followers/Daysapro?label=Seguir&style=social)](https://github.com/Daysapro) [![like_tag](https://img.shields.io/github/stars/Daysapro/cryptonomicon?label=Favorito&style=social)](https://github.com/Daysapro/cryptonomicon)

[![symmetric_tag](https://img.shields.io/:simétrico-2ecc71.svg?labelColor=3A0EB5&color=3A0EB5)]() [![xor_tag](https://img.shields.io/:XOR-2ecc71.svg?labelColor=3A0EB5&color=3A0EB5)]()


> Las bases sobre las que se construyen los cifrados simétricos modernos.

Los modos de operación son algoritmos que proveen una capa adicional de seguridad a los cifrados simétricos. Al utilizar cifrados como [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) y [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher)) es necesario dividir el mensaje original en distintos bloques para encriptarlos por separado. Teniendo una única clave, una opción es cifrar cada bloque de manera independiente y concatenar las salidas para obtener el mensaje cifrado final. Esto es lo que se conoce como modo ECB y presenta debilidades en términos de confidencialidad. 

Para superar estas limitaciones, se han desarrollado numerosas alternativas al modo ECB, que aprovechan las propiedades de la [operación XOR](https://en.wikipedia.org/wiki/Exclusive_or) y otras técnicas para garantizar la seguridad. Estas alternativas marcan la dirección de lo que actualmente se considera seguro y se van a explicar en esta publicación.


## Requisitos

Para comprender los modos de operación de cifrados de bloques, se recomienda tener conocimientos básicos sobre cifrados simétricos y el entendimiento del funcionamiento de la operación XOR. Así mismo, los ejemplos proporcionados estarán programados en Python.


## Índice

1. [Introducción](#introducción)
    1. [Ejemplo de aplicación](#ejemplo-de-aplicación)
    2. [Sistema de representación 1: esquemas](#sistema-de-representación-1-esquemas)
    3. [Sistema de representación 2: ecuaciones](#sistema-de-representación-2-ecuaciones)
2. [Modos de operación de bloques tradicionales](#modos-de-operación-de-bloques-tradicionales)
    1. [ECB (Electronic codebook)](#ecb-electronic-codebook)
        1. [Esquema](#esquema)
        2. [Ecuaciones](#ecuaciones)
        3. [Criptoanálisis](#criptoanálisis)
            1. [Byte-at-a-time](#byte-at-a-time)
    2. [CBC (Cipher block chaining)](#cbc-cipher-block-chaining)
        1. [Esquema](#esquema-1)
        2. [Ecuaciones](#ecuaciones-1)
        3. [Criptoanálisis](#criptoanálisis-1)
            1. [Padding oracle attack](#padding-oracle-attack)
            2. [Bit-flipping attack](#bit-flipping-attack)
            3. [IV = key](#iv--key)
    3. [PCBC (Propagation cipher block chaining)](#pcbc-propagation-cipher-block-chaining)
        1. [Esquema](#esquema-2)
        2. [Ecuaciones](#ecuaciones-2)
        3. [Criptoanálisis](#criptoanálisis-2)
3. [Modos de operación de bloques en flujo](#modos-de-operación-de-bloques-en-flujo)
    1. [CFB (Cipher feedback)](#cfb-cipher-feedback)
        1. [Esquema](#esquema-3)
            1. [CFB tradicional](#cfb-tradicional)
            2. [CFB-s](#cfb-s)
        2. [Ecuaciones](#ecuaciones-3)
            1. [CFB tradicional](#cfb-tradicional-1)
            2. [CFB-s](#cfb-s-1)
        3. [Criptoanálisis](#criptoanálisis-3)
            1. [Zerologon](#zerologon)
    2. [OFB (Output feedback)](#ofb-output-feedback)
        1. [Esquema](#esquema-4)
        2. [Ecuaciones](#ecuaciones-4)
        3. [Criptoanálisis](#criptoanálisis-4)
            1. [Ataque de texto claro conocido](#ataque-de-texto-claro-conocido)
    3. [CTR (Counter)](#ctr-counter)
        1. [Esquema](#esquema-5)
        2. [Ecuaciones](#ecuaciones-5)
        3. [Criptoanálisis](#criptoanálisis-5)
            1. [Nonce reutilizado](#nonce-reutilizado)
            2. [Bit-flipping attack](#bit-flipping-attack-1)


## Introducción

Un modo de operación de cifrado de bloques determina la forma por la que se aplica la encriptación para cada bloque en un mensaje que va a ser encriptado con un sistema simétrico por bloques. Es decir, no interviene de ninguna forma en el proceso de cifrado sino que construye unos pasos previos y posteriores que mejoran la privacidad del mensaje. 

Estos modos de operación son indispensables en la criptografía actual, ya que sin ellos no existiría ningún cifrado de bloques seguro. Su análisis es importante debido a que a lo largo de los años las implementaciones deficientes de los mismos han producido un gran porcentaje de las vulnerabilidades relacionadas con los cifrados simétricos.


### Ejemplo de aplicación

El cifrado AES requiere de un tamaño de bloques de 128 bits. 
- Caso 1. Se necesita cifrar usando AES un mensaje de 512 bits. El mensaje se divide en cuatro bloques de 128 bits y se establece el modo de operación. 
La resolución de este caso es trivial. La división en bloques es exacta por lo que los cuatro bloques de 128 bits contendrán toda la información del mensaje.
- Caso 2. Se necesita cifrar usando AES un mensaje de 140 bits. Se divide en dos bloques, uno con 128 bits y el otro con 12. AES no podría encriptar un bloque ya que no tiene la longitud exacta de 128 bits. Se tendrían que usar [técnicas de relleno](https://en.wikipedia.org/wiki/Padding_(cryptography)) para completar el último bloque, y una vez rellenado se aplica el modo de operación.


### Sistema de representación 1: esquemas

Durante la explicación de cada modo, se van a utilizar de referencia distintos esquemas que representan cada operación relevante, por lo que es importante entender qué significa cada componente.

<p align="center">
    <img width="40%" src="images/components.png"> 
</p>

* **Cifrado por bloques**. Encripta el bloque usando el cifrado simétrico.
* **Descifrado por bloques**. Desencripta el bloque usando el cifrado simétrico.
* **Mensaje en claro**. Mensaje a encriptar.
* **Mensaje cifrado**. Mensaje producto de la encriptación.
* **Clave**. Clave secreta del cifrado simétrico.
* **XOR**. Realiza la operación XOR de los dos elementos entrantes.
* **Vector inicializador (IV)**. Bloque de bits generados aleatoriamente para aumentar el caos.


### Sistema de representación 2: ecuaciones

Cada modo de operación se puede además definir como un conjunto de ecuaciones de cifrado y descifrado. El uso de este sistema de representación facilita el entendimiento de los mismos. Por ejemplo, el cifrado usando el modo ECB se podría representar como:

$$C_i = E_K(P_i)$$

Cada bloque $i$ de texto en claro $P$ es encriptado $E$ con la clave $K$ resultando en los bloques $C$.

* $C_i$. Bloque $i$ del texto cifrado.
* $P_i$. Bloque $i$ del texto en claro.
* $E_K$. Cifrado con la clave $K$.
* $D_K$. Descifrado con la clave $K$.
* $IV$. Vector inicializador.


## Modos de operación de bloques tradicionales

La diferenciación entre estos modos y los modos de flujo es meramente teórica. La forma de uso y la utilidad es la misma para todos los casos. En lo que llamaremos modos de operación de bloques tradicionales, el mensaje en claro será el que, en combinación o no de otros factores, pasará por el componente de cifrado para acabar convirtiéndose en el mensaje cifrado. Por otro lado, en los modos de operación de bloques en flujo el mensaje en claro es operado a través de XOR con bloques pseudoaleatorios para obtener el mensaje cifrado. Estos bloques pseudoaleatorios habrán pasado por el sistema simétrico en cuestión y otras operaciones.


### ECB (Electronic codebook)

ECB es el método más simple de organizar los bloques en los modos de operación. El mensaje es dividido en bloques y se encriptan de manera independiente. Los mensajes resultado se concatenan formando el mensaje cifrado final.


#### Esquema

<p align="center">
    <img width="50%" src="images/ecb_e.png"> 
</p>

<p align="center">
    <img width="50%" src="images/ecb_d.png"> 
</p>


#### Ecuaciones

$$C_i = E_K(P_i)$$

$$P_i = D_K(P_i)$$


#### Criptoanálisis

Se considera que el problema del modo ECB recae en la falta de difusión del caos. Un bloque de texto claro siempre producirá exactamente el mismo texto cifrado cuando se usa la misma clave. Por tanto, dentro de un mismo proceso de cifrado con un número considerable de bloques, este modo no será capaz de ocultar posibles patrones de datos. Este problema se puede representar cifrando los píxeles en bruto de una imagen utilizando un cifrado simétrico y el modo ECB.

<div align="center">
    <img width="40%" src="images/daysapro.png">
    <img width="40%" src="images/ecb_daysapro.png">
</div>

A la derecha, aún habiendo cifrado con AES utilizando ECB, se sigue leyendo la palabra sin problema.

<div align="center">
    <img width="40%" src="images/cryptonomicon_logo.png">
    <img width="40%" src="images/ecb_cryptonomicon_logo.png">
</div>

Con imágenes con menos patrones se siguen percibiendo algunas franjas de color.

> [Ver implementación de cifrado de imágenes usando AES en modo ECB.](scripts/ecb_image_cipher.py)


##### Byte-at-a-time

En este ataque se necesita tener acceso a una entrada de datos que devuelve ```AES_ECB(input || secret, key)```. El objetivo es recuperar la cadena secreta teniendo únicamente control de la entrada. 

Un caso real en el que se podría encontrar una situación parecida puede ser la creación de una petición de un sistema de inicio de sesión en el que el usuario introduce un nombre que se concatena con una contraseña definida. Esta petición se envía cifrada para no exfiltrar la contraseña y el atacante puede observar las salidas de sus entradas. 

> [Ver implementación de petición vulnerable usando AES en modo ECB.](scripts/ecb_vulnerable_query.py)

La situación del caso práctico es ```AES_ECB("{'usuario':" || input || ", 'password': " || secret || "}", key)``` y aunque es vulnerable con fines didácticos se explica el ataque con el ejemplo inicial:

```AES_ECB(input || secret, key)```

AES utiliza un tamaño de bloque de 128 bits. En cada bloque pueden ser almacenados 16 caracteres. 

1. Se envía como entrada una secuencia de datos conocidos del tamaño en bytes menos uno. Por ejemplo, con nuestro tamaño de bloque de 16 bytes (128 bits), se envían 15 caracteres ```AAAAAAAAAAAAAAA```.

2. Nuestro primer bloque cifrado, siguiendo la teoría del modo ECB, será ```AES_ECB(AAAAAAAAAAAAAAA || s0, key)``` siendo $s_0$ en primer byte de la cadena secreta.

3. Se cifran las 256 combinaciones posibles de ese primer byte. ```AES_ECB(AAAAAAAAAAAAAAA || A, key)```, ```AES_ECB(AAAAAAAAAAAAAAA || B, key)```, ```AES_ECB(AAAAAAAAAAAAAAA || C, key)```... Uno de ellos será igual al bloque generado en el paso 2. Ese byte se corresponde a $s_0$.

4. Para conseguir los siguientes bytes se disminuye el número de As. Imaginemos que el primer byte del secreto es la letra f. Para el segundo byte se calcula el bloque de referencia ```AES_ECB(AAAAAAAAAAAAAA, key)``` y se hará fuerza bruta sobre $s_1$ generando los bloques ```AES_ECB(AAAAAAAAAAAAAA || f || s1, key)```.De esta manera se puede obtener el secreto si su longitud es menor que 16 bytes. 

5. Para longitudes mayores que el tamaño del bloque el procedimiento sigue siendo el mismo pero tomando como referencia otro bloque. Siendo el secreto ```flag{byte_at_a_time_attack}``` con los primeros 4 pasos se ha obtenido la cadena ```flag{byte_at_a_t```. Se cifran de nuevo 15 As y se mira el segundo bloque. El segundo bloque es ```AES_ECB(lag{byte_at_a_t || s16, key)```. Se generan todos los bloques con $s_{16}$ y se puede continuar este proceso hasta recuperar todos los caracteres.

> [Ver implementación del ataque byte-at-a-time al modo ECB.](scripts/ecb_byte_at_a_time.py)


### CBC (Cipher block chaining)

En el modo CBC, cada bloque de texto en claro es operado con XOR con el texto cifrado del anterior bloque. El resultado de esa operación es el que se encripta.


#### Esquema

<p align="center">
    <img width="60%" src="images/cbc_e.png"> 
</p>

<p align="center">
    <img width="60%" src="images/cbc_d.png"> 
</p>


#### Ecuaciones

Si $i = 0$:

$$C_0 = E_K(P_0 \oplus IV)$$

$$P_0 = D_K(C_0) \oplus IV$$

En otro caso:

$$C_i = E_K(P_i \oplus C_{i - 1})$$

$$P_i = D_K(C_i) \oplus C_{i - 1}$$


#### Criptoanálisis

El modo CBC ha sido considerado vulnerable en numerosas ocasiones. Sus [propiedades de robustez o la ignorancia](https://www.quora.com/Why-is-the-CBC-mode-of-encryption-still-used-instead-of-CTR-mode-even-though-CBC-mode-has-proven-to-be-vulnerable-ex-poodle-attack) de algunas empresas han podido ser las responsables de que aún a día de hoy siga en uso. Sin embargo, ninguna entidad ha podido pasar por alto la vulnerabilidad conocida como [POODLE](https://en.wikipedia.org/wiki/POODLE).


##### Padding oracle attack

La palabra POODLE proviene de las iniciales Padding Oracle On Downgraded Legacy Encryption ([CVE-2014-3566](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2014-3566)). La teoría de este ataque fue publicada en 2002 por el criptólogo [Serge Vaudenay](https://en.wikipedia.org/wiki/Serge_Vaudenay), y no solo afecta al modo CBC, sino que también se pueden encontrar vulnerabilidades asociadas en algunos [modos de relleno de criptografía asimétrica (OAEP)](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding).

En la sección de [ejemplo de aplicación](#ejemplo-de-aplicación) se explica que si un bloque de información no cumple con la cantidad de bits requerida por el cifrado simétrico, se completa con valores definidos por un algoritmo de rellenado o padding. 

El algoritmo de padding utilizado en el modo CBC es el [Public Key Cryptography Standard (PKCS #7)](https://en.wikipedia.org/wiki/PKCS_7), el cual introduce repetidamente el número de bytes necesario para completar el bloque. En otras palabras, si al último bloque le faltan 4 bytes, se introducen los bytes ```\x04\x04\x04\x04```.

Para que este vector de ataque esté presente, el usuario debe tener acceso a un sistema que revele información de si en un proceso de descifrado, manejado por el usuario, se ha producido algún error de relleno. Con la aparición o no de este error se obtienen datos de la información cifrada. Además, se supone que la clave es estática durante todo el ataque.

Se valora un nuevo bloque de interés en nuestro esquema de desencriptado del modo CBC. Es un bloque intermedio $I$, que resulta de descifrar un bloque $i$ antes de hacer la operación XOR con el texto cifrado del bloque anterior.

<p align="center">
    <img width="60%" src="images/cbc_i.png"> 
</p>

$$I_i = D_K(C_i)$$

$$P_0 = I_0 \oplus IV$$

$$P_i = I_i \oplus C_{i - 1}$$

Este bloque es de suma importancia, ya que permitiría obtener el texto en claro de los textos cifrados que lo generaron.

En este ataque se manipulan los bloques de textos cifrados y el vector inicializador para obtener información de los bloques intermedios, lo que conduce a la recuperación del texto en claro. 

1. El proceso de descifrado se reduce a un solo bloque.

<p align="center">
    <img width="40%" src="images/cbc_r.png"> 
</p>

2. Se introduce el bloque de mensaje cifrado que queremos descifrar. El bloque de mensaje cifrado anterior o $IV$ del esquema es un bloque auxiliar sobre el que se va a construir el ataque. Sabemos que el mensaje en claro es el resultado de eliminar el relleno a la salida de la operación XOR. Por ejemplo, si el último bloque del mensaje claro rellenado con el algoritmo PKCS #7 es ```je de ejemplo\x03\x03\x03``` el resultado será ```je de ejemplo```. ¿Qué sucedería si la operación XOR diera como resultado ```je de ejemplo\x03\x03\x02```? La función de eliminación del relleno fallaría y podríamos detectar el error. Este comportamiento es el que se explota por medio del bloque auxiliar.

3. El bloque auxiliar se inicializa con ceros. Al reducir el problema a un solo bloque, este bloque auxiliar se introduce como el vector inicializador del esquema CBC. Se prueban todas las combinaciones para el último byte en busca del byte que no produzca error de relleno. De esta manera, el mensaje en claro será $P^\prime_{15} = IV_{15} \oplus I_{15}$.
Nótese que en este caso los índices marcan las posiciones de los bytes dentro del bloque. Se conoce $IV_{15}$ (byte introducido por fuerza bruta) y, al ser el relleno correcto, $P^\prime_{15}$, que será 1. De aquí se obtiene el último byte del bloque intermedio.
Este último byte de los bloques puede ser el más problemático, ya que pueden surgir falsos positivos. Un ejemplo sería si el byte $P^\prime_{14}$ tuviera el valor de 2. En ese caso, $P^\prime_{15}$ daría relleno correcto para 1 y para 2. Para evitar este problema se recomienda hacer una doble comprobación cambiando el penúltimo byte sumando una unidad. 

4. Para los bytes siguientes el proceso es similar, con la diferencia de que para encontrar $I_{14}$ se necesitan que $P^\prime_{14}$ y $P^\prime_{15}$ sean iguales a 2. Aprovechando las propiedades de XOR y conociendo $I_{15}$, el último byte de nuestro $IV$ malicioso será $IV_{15} = I_{15} \oplus 2$. Cuando se opere por la función en el XOR se hará $I_{15} \oplus I_{15} \oplus 2 = 0 \oplus 2 = 2$ y volvemos al proceso del paso 3 con el byte 14 buscando el deseado 2. $I_{14}$ será $IV_{14} \oplus 2$.

5. Estos pasos se pueden repetir para cualquier bloque de texto cifrado, y una vez obtenidos todos los bloques intermedios, solo es necesario realizar la operación XOR con el vector inicializador y los bloques cifrados iniciales.

> [Ver implementación del ataque padding oracle al modo CBC.](scripts/cbc_padding_oracle_attack.py)


##### Bit-flipping attack

Un servidor web tramita peticiones de inicio de sesión según los siguientes parámetros:

```user=user&password=password&admin=0```

Los campos ```user``` y ```password``` son introducidos por el cliente mientras que el campo ```admin``` se envía por defecto en 0. Como la empresa no quiere que cualquier cliente pueda introducir el valor ```admin``` 1 y entrar al panel de control, envía la petición cifrada utilizando el sistema de cifrado AES en modo CBC, petición que pasa por el cliente.

En esta situación un atacante puede manipular el valor de ```admin``` sin conocer el valor de la clave.

1. Se calcula la posición del carácter que se quiere modificar. En el caso de ```user=user&password=password&admin=0``` el primer bloque sería ```user=user&passwo```, el segundo ```rd=password&admi``` y el tercero ```n=0\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13```. El byte que queremos modificar es el tercero del tercer bloque.

2. Considerando el esquema de descifrado de un bloque en modo CBC:

<p align="center">
    <img width="40%" src="images/cbc_r.png"> 
</p>

Se conoce el byte del bloque cifrado anterior, y sabemos que nuestro byte de interés en el mensaje en claro es 0. Por tanto, se puede calcular el byte del bloque intermedio. Con esta información, se puede forzar que el byte del bloque anterior operado por XOR con el byte intermedio sea 1. Se cambia ese byte y ```admin``` vale 1.

Por ejemplo, nuestro segundo bloque ```rd=password&admi``` cifrado con una clave aleatoria es ```\xd2#\xcb\x8c\xceA<\xddz\x9d\x0c\x03\xc5\xc2\xc2\x8c```:

$$I_2 = ord(/xcb) \oplus ord(0) = 61 \oplus 48 = 13$$

Siendo ```ord``` la operación de convertir un byte a su representación entera. Nótese que en este caso los índices marcan las posiciones de los bytes dentro de los bloques.

Se busca que $P^\prime_2$ sea 1, por lo que:

$$C^\prime_2 = I_2 \oplus P^\prime_2 = 13 \oplus ord(1) = 13 \oplus 60 = 49$$

El bloque cifrado nuevo debe ser: ```\xd2#1\x8c\xceA<\xddz\x9d\x0c\x03\xc5\xc2\xc2\x8c```, siendo ```1``` la conversión en bytes del número 49.

Este ataque implica la manipulación del bloque cifrado anterior, que tras pasar por el descifrado perderá por completo el sentido. En situaciones en las que ese bloque se interprete posteriormente el programa intérprete podría detectar el ataque y mitigarlo.

> [Ver implementación del ataque bit-flipping al modo CBC.](scripts/cbc_bit_flipping_attack.py)


##### IV = key

Hay empresas que fruto del desconocimiento usaron como vector inicializador la misma clave de cifrado y, como es lógico, no lo hacían público. Esta práctica, aunque supone una mejora en consumo de recursos computacionales, es muy poco segura, como se demuestra a continuación.

1. Se cifra un mensaje de un bloque $P_0$.

$$C_0 = E_K(P_0 \oplus IV)$$

$$C_0 = E_K(P_0 \oplus key)$$

$$P_0 = D_K(C_0) \oplus key$$

2. Se descifra un mensaje de dos bloques $(0, C_0)$, siendo 0 un bloque completo de ceros.

$$P^\prime_0 = D_K(0) \oplus key$$

$$P^\prime_1 = D_K(C_0) \oplus 0 = D_K(C_0)$$

3. Se calcula $P_0 \oplus P^\prime_1$.

$$P_0 \oplus P^\prime_1 = D_K(C_0) \oplus key \oplus D_K(C_0) = key$$


### PCBC (Propagation cipher block chaining)

Se considera una evolución del modo CBC. El mensaje a cifrar se opera con XOR con el texto cifrado y el texto original del bloque anterior.


#### Esquema

<p align="center">
    <img width="60%" src="images/pcbc_e.png"> 
</p>

<p align="center">
    <img width="60%" src="images/pcbc_d.png"> 
</p>


#### Ecuaciones

Si $i = 0$:

$$C_0 = E_K(P_0 \oplus IV)$$

$$P_0 = D_K(C_0) \oplus IV$$

En otro caso:

$$C_i = E_K(P_i \oplus P_{i - 1} \oplus C_{i - 1})$$

$$P_i = D_K(C_i) \oplus C_{i - 1} \oplus P_{i - 1}$$


#### Criptoanálisis

El uso del modo PCBC siempre ha sido muy reducido. Se utilizó en el protocolo de autentificación [Kerberos](https://en.wikipedia.org/wiki/Kerberos_(protocol)) en su versión 4, pero acabó siendo descartado en la posterior. Pese a que el uso de PCBC fuera muy llamativo por sus propiedades de propagación del caos, el motivo detrás de la retirada fue el descubrimiento de un error de propagación entre bloques, ya que si se intercambian dos bloques de cifrado adyacentes el descifrado de los bloques siguientes no era afectado. Además, en la implementación las pruebas de integración de mensajes comprobaban los mensajes en claro de los últimos bloques, pruebas que no detectaban el error.

$$P_i = D_K(C_i) \oplus C_{i - 1} \oplus P_{i - 1}$$

$$P_{i - 1} = D_K(C_{i - 1}) \oplus C_{i - 2} \oplus P_{i - 2}$$

$$P_{i - 2} = D_K(C_{i - 2}) \oplus C_{i - 3} \oplus P_{i - 3}$$

$$P_i = D_K(C_i) \oplus C_{i - 1} \oplus D_K(C_{i - 1}) \oplus C_{i - 2} \oplus D_K(C_{i - 2}) \oplus C_{i - 3} \oplus P_{i - 3}$$

Intercambiando $C_{i - 1}$ por $C_{i - 2}$ el resultado de nuestro $P_i$ es el mismo.

$$P_i = D_K(C_i) \oplus C_{i - 2} \oplus D_K(C_{i - 2}) \oplus C_{i - 1} \oplus D_K(C_{i - 1}) \oplus C_{i - 3} \oplus P_{i - 3}$$


## Modos de operación de bloques en flujo

Como se ha explicado anteriormente, en los modos de operación de bloques en flujo el mensaje en claro es operado a través de XOR con bloques pseudoaleatorios para obtener el mensaje cifrado.

Por las propiedades de la operación XOR, el uso del bloque de descifrado no es necesario en los siguientes esquemas. Denominando $I_i$ a los bloques pseudoaleatorios:

$$C_i = I_i \oplus P_i$$

$$P_i = I_i \oplus C_i$$

Como $I_i$ es el resultado de un bloque cifrado, siempre se utiliza el módulo de cifrar del cifrado simétrico incluso obteniendo los bloques $P_i$.


### CFB (Cipher feedback)

En este modo la entrada al cifrado simétrico es el bloque cifrado anterior. El resultado de la encriptación se opera mediante XOR con el mensaje en claro produciendo el siguiente bloque.

Es importante conocer que en el modo CFB, según las recomendaciones [NIST SP800-38A](#https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf), se puede definir con un parámetro entero $s$, siendo $1 \leq s \leq b$ con $b$ tamaño del bloque. Este uso construye el conjunto de modos CFB-s, como CFB-1, CFB-8, CFB-128... Mientras que el esquema presenta pocos cambios respecto al modo CFB tradicional, se incorpora en sus ecuaciones una rotación de $s$ bits que añade más aleatoriedad al cifrado. 


#### Esquema

##### CFB tradicional

<p align="center">
    <img width="60%" src="images/cfb_e.png"> 
</p>

<p align="center">
    <img width="60%" src="images/cfb_d.png"> 
</p>


##### CFB-s

<p align="center">
    <img width="60%" src="images/cfbs_e.png"> 
</p>

<p align="center">
    <img width="60%" src="images/cfbs_d.png"> 
</p>


#### Ecuaciones

##### CFB tradicional

Si $i = 0$:

$$C_0 = E_K(IV) \oplus P_0$$

$$P_0 = E_K(IV) \oplus C_0$$

En otro caso:

$$C_i = E_K(C_{i - 1}) \oplus P_i$$

$$P_i = E_K(C_{i - 1}) \oplus C_i$$


##### CFB-s

$$I_0 = IV$$

$$I_i = ((I_{i - 1} << s) | C_i) \bmod 2^b$$

$$C_i = MSB_s(E_K(I_{i - 1})) \oplus P_i$$

$$P_i = MSB_s(E_K(I_{i - 1})) \oplus C_i$$

$MSB_s$ representa la operación de $s$ bits más significativos. Nótese que los bloques $I$ son bloques intermedios anteriores al cifrado, no posteriores al mismo.


#### Criptoanálisis

##### Zerologon

Zerologon es el nombre que recibe la vulnerabilidad [CVE-2020-1472](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472) que afectaba a todos los equipos que usaban el protocolo remoto Netlogon (MS-NRPC) de Microsoft. Debido a un error en la implementación de un sistema de cifrado AES-CFB8, un atacante podía iniciar sesión sin credenciales como controlador de dominio en un servicio de directorio activo.

En septiembre 2020, un joven llamado Tom Tervoort publica un [artículo](https://www.secura.com/uploads/whitepapers/Zerologon.pdf) en el que demuestra que introduciendo un vector inicializador y un mensaje entero de ceros, dada una clave aleatoria, existe una probabilidad entre 256 de que el resultado de un cifrado AES-CFB8 fuera un mensaje cifrado entero de ceros.

1. Se define un vector inicializador $IV$ de 16 bytes y un mensaje $P$ de 8 bytes entero de ceros.

2. Según CFB-8:

$$I_0 = IV$$

$$C_0 = MSB_8(E_K(IV)) \oplus P_0$$

La probabilidad de que el primer byte de $E_K(IV)$ fuera 0, byte que corresponde a los 8 bits más significativos ($MSB_8$), es una entre los 256 valores posibles de un byte. Cuando esto ocurre el primer byte del mensaje cifrado es 0:

$$C_0 = 0 \oplus P_0 = 0 \oplus 0 = 0$$

3. El nuevo bloque a pasar por el módulo cifrador se forma como $IV << 8 | C_0$. El $IV$ desplazado 8 bits a la derecha es todo ceros y $C_0$ también. Tras el cifrado se volverá a obtener en el primer byte un 0, por lo que $C_1$ tendrá el mismo destino que $C_0$.

4. Y así, iterando sobre el $IV$ y los nuevos bytes cifrados, se formará un mensaje cifrado entero de ceros.

Aplicando la teoría al caso de la vulnerabilidad, Tervoort descubrió que en el protocolo Netlogon el $IV$ siempre era un vector de 16 bytes de ceros. Al usuario, por otro lado, le solicita una credencial de acceso y un parámetro denominado challenge, ambos con una longitud de 8 bytes. Esta credencial es el mensaje en claro que cifraba obteniendo el mensaje cifrado, el cual se comprueba si es igual al challenge. Sabiendo las características del vector inicializador y sin límite de intentos de inicio de sesión, nada impide a un atacante introducir 256 veces dos vectores de ceros a credencial y challenge y acceder al directorio activo.

> [Ver demostración de la generación de mensaje cifrado entero de ceros de la vulnerabilidad Zerologon.](scripts/cfb_zerologon.py)


### OFB (Output feedback)

El modo OFB presenta un comportamiento diferente al resto de modos. La salida del bloque de cifrado es la entrada del cifrado del siguiente bloque, por lo que partiendo del vector inicializador $IV$ el texto cifrado del bloque $i$ será el XOR entre el texto claro e $i$ veces encriptado $IV$.


#### Esquema

<p align="center">
    <img width="60%" src="images/ofb_e.png"> 
</p>

<p align="center">
    <img width="60%" src="images/ofb_d.png"> 
</p>


#### Ecuaciones

Si $i = 0$:

$$C_0 = E_K(IV) \oplus P_0$$

$$P_0 = E_K(IV) \oplus C_0$$

Si $i = 1$:

$$C_1 = E_K(E_K(IV)) \oplus P_i$$

$$P_1 = E_K(E_K(IV)) \oplus C_i$$

Si $i = 2$:

$$C_2 = E_K(E_K(E_K(IV))) \oplus P_i$$

$$P_2 = E_K(E_K(E_K(IV))) \oplus C_i$$

$$...$$


#### Criptoanálisis

##### Ataque de texto claro conocido

Un ataque de texto claro conocido o known-plaintext attack (KPA) es un modelo de ataque en el que el atacante puede obtener información confidencial en base a un texto plano y su respectivo texto cifrado.

En el modo OFB este ataque permite la lectura íntegra de los mensajes trasmitidos en el caso de que se cifren varios de ellos reutilizando clave y vector inicializador, gracias a las propiedades de la operación XOR.

Es aplicable debido a la generación de bloques pseudoaleatorios que se puede ver en su esquema. Todos estos bloques dependen únicamente del vector inicializador y de la clave utilizada en el cifrado.

Consideramos $E_K(E_K...(IV))$ el bloque intermedio $I_i$:

$$C_i = I_i \oplus P_i$$

$$I_i = C_i \oplus P_i$$

En base a los bloques de texto cifrado y los bloques de texto claro se recuperan todos los bloques intermedios. Estos bloques intermedios se pueden operar XOR con otros textos cifrados con la misma clave y vector inicializador recuperando así el mensaje original:

$$P^\prime_i = I_i \oplus C^\prime_i$$

> [Ver implementación del ataque de texto claro conocido al modo OFB.](scripts/ofb_known_plaintext_attack.py)


### CTR (Counter)

El modo CTR es el modo más aceptado y usado en la actualidad. Se parte desde un $IV$ el cual es concatenado, sumado u operado con XOR con un contador. Este contador va aumentando en una unidad por cada bloque y es el bloque resultado de la encriptación $IV$ y contador el que se opera por XOR con el texto en claro. Pese a que el contador de incremento de uno en uno es el más usado no es el único existente. Cualquier función capaz de producir una secuencia sin repeticiones en intervalos de tiempo lo suficientemente amplios podría ser un contador válido.

La forma en la que se une el vector inicializador con el contador depende de la seguridad de la generación del vector y del servicio al que se disponga el sistema criptográfico.

El vector inicializador $IV$ en estos casos se suele denominar [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce).


#### Esquema

<p align="center">
    <img width="60%" src="images/ctr_e.png"> 
</p>

<p align="center">
    <img width="60%" src="images/ctr_d.png"> 
</p>


#### Ecuaciones

Con un contador de incremento de uno:

$$C_i = E_K(IV | i) \oplus P_i$$

$$P_i = E_K(IV | i) \oplus C_i$$


#### Criptoanálisis

##### Nonce reutilizado

En una exfiltración de datos se obtienen una serie de textos cifrados junto con la información de que han sido cifrados con la misma clave y con el mismo nonce. El contador también se ha iniciado en el mismo valor para todos los casos.

Aunque no se conoce ningún texto en claro sabemos que:

$$C_i = I_i \oplus P_i$$
 
$$I_i = C_i \oplus P_i$$

Teniendo los bloques $C_i$ se pueden obtener algunas conclusiones. Si los textos originales sabemos que están en inglés, sería altamente probable que alguno de todos ellos contuviera la palabra ```the```. Se puede hacer la operación XOR con cada consecución de 3 bytes de los textos cifrados y cada resultado es un fragmento candidato de los bloques intermedios. El fragmento candidato se confirmará haciendo XOR respecto al resto de textos cifrados. Si los resultados son legibles en inglés, se confirma la hipótesis.

Este método basado en sustituciones tiene dificultades a la hora de ser automatizado ya que requiere de una persona capaz de valorar si un texto es legible en inglés o no.

Otra alternativa mejor es considerar el caso como un único texto que utiliza una clave cíclica XOR.

1. Se toma el texto cifrado de menor longitud.
2. Se ajustan los textos de mayor longitud a la longitud del menor.
3. Se sabe que todos esos fragmentos de textos cifrados han sido operados según la operación XOR con la misma clave. 
4. Se construyen conjuntos de los bytes $i$ de cada fragmento de texto cifrado. Se sabe que estos conjuntos han sido operados con XOR con el mismo byte. Se realiza un ataque de fuerza bruta con todos los bytes y se selecciona el resultado más creíble de cada conjunto, teniendo en cuenta la información de que el mensaje está en inglés y descartando bytes no imprimibles u otros resultados sin sentido. Este paso supone la mayor complicación del ejercicio y requiere de un evaluador de textos, el cuál podría ser un análisis de frecuencias.
5. Concatenando los bytes que obtienen los mejores resultados se obtiene la clave.

> [Ver implementación de un ataque estadístico a un nonce reutilizado en el modo CTR.](scripts/ctr_fixed_nonce.py)


##### Bit-flipping attack

El ataque bit-flipping en los modos OFB o CTR es mucho más fácil que en el modo CBC. El cambio de un byte en el texto claro o cifrado solo provoca cambios en el texto cifrado o claro respectivo. Por tanto, para cambiar un byte del texto claro solo hay que saber su posición y qué valor a introducir va a causar el efecto deseado.

Se recupera el ejemplo utilizado en el bit-flipping del modo CBC. 

Un servidor web tramita peticiones de inicio de sesión según los siguientes parámetros:

```user=user&password=password&admin=0```

Los campos ```user``` y ```password``` son introducidos por el cliente mientras que el campo ```admin``` se envía por defecto en 0. Como la empresa no quiere que cualquier cliente pueda introducir el valor ```admin``` 1 y entrar al panel de control, envía la petición cifrada utilizando el sistema de cifrado AES en modo CTR, petición que pasa por el cliente.

1. Mismo primer paso que en el modo CBC. Se calcula la posición del carácter que se quiere modificar. En el caso de ```user=user&password=password&admin=0``` el primer bloque sería ```user=user&passwo```, el segundo ```rd=password&admi``` y el tercero ```n=0\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13```. El byte que queremos modificar es el tercero del tercer bloque.

2. Según las ecuaciones del modo CTR:

$$P_i = I_i \oplus C_i$$

$$I_i = C_i \oplus P_i$$

Nuestro byte de interés en el mensaje en claro es 0. Por tanto, se puede calcular el byte del bloque intermedio. Con esta información, se puede forzar que el byte del bloque anterior operado por XOR con el byte intermedio sea 1. Se cambia ese byte y ```admin``` vale 1.

Por ejemplo, si nuestro tercer bloque cifrado fuera ```\xd2#\xcb\x8c\xceA<\xddz\x9d\x0c\x03\xc5\xc2\xc2\x8c```:

$$I_2 = ord(/xcb) \oplus ord(0) = 61 \oplus 48 = 13$$

Siendo ```ord``` la operación de convertir un byte a su representación entera. Nótese que en este caso los índices marcan las posiciones de los bytes dentro de los bloques.

Se busca que $P^\prime_2$ sea 1, por lo que:

$$C^\prime_2 = I_2 \oplus P^\prime_2 = 13 \oplus ord(1) = 13 \oplus 60 = 49$$

El bloque cifrado nuevo debe ser: ```\xd2#1\x8c\xceA<\xddz\x9d\x0c\x03\xc5\xc2\xc2\x8c```, siendo ```1``` la conversión en bytes del número 49.

Además, a diferencia que en el modo CBC, el resto de bloques no se ven afectados por este cambio.

> [Ver implementación del ataque bit-flipping al modo CTR.](scripts/ctr_bit_flipping_attack.py)