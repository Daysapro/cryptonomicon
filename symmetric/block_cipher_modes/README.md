# Modos de operación de cifrado de bloques

[![development_tag](https://img.shields.io/badge/en%20desarrollo-50%25-brightgreen)]()

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
    2. [CBC (Cipher block chaining)](#cbc-cipher-block-chaining)
        1. [Esquema](#esquema-1)
        2. [Ecuaciones](#ecuaciones-1)
    3. [PCBC (Propagation cipher block chaining)](#pcbc-propagation-cipher-block-chaining)
        1. [Esquema](#esquema-2)
        2. [Ecuaciones](#ecuaciones-2)
3. [Modos de operación de bloques en flujo](#modos-de-operación-de-bloques-en-flujo)
    1. [CFB (Cipher feedback)](#cfb-cipher-feedback)
        1. [Esquema](#esquema-3)
        2. [Ecuaciones](#ecuaciones-3)
    2. [OFB (Output feedback)](#ofb-output-feedback)
        1. [Esquema](#esquema-4)
        2. [Ecuaciones](#ecuaciones-4)  
    3. [CTR (Counter)](#ctr-counter)
        1. [Esquema](#esquema-5)
        2. [Ecuaciones](#ecuaciones-5)


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
* **Vector inicializador (IV)**. Bloque de bits para aumentar la aleatoriedad.


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


## Modos de operación de bloques en flujo

Como se ha explicado anteriormente, en los modos de operación de bloques en flujo el mensaje en claro es operado a través de XOR con bloques pseudoaleatorios para obtener el mensaje cifrado.

Por las propiedades de la operación XOR, el uso del bloque de descifrado no es necesario en los siguientes esquemas. Denominando $S_i$ a los bloques pseudoaleatorios:

$$C_i = S_i \oplus P_i$$

$$P_i = S_i \oplus C_i$$

Como $S_i$ es el resultado de un bloque cifrado, se tiene que utilizar el módulo de cifrar del cifrado simétrico incluso obteniendo los bloques $P_i$.


### CFB (Cipher feedback)

En este modo la entrada al cifrado simétrico es el bloque cifrado anterior. El resultado de la encriptación se opera mediante XOR con el mensaje en claro produciendo el siguiente bloque.


#### Esquema

<p align="center">
    <img width="60%" src="images/cfb_e.png"> 
</p>

<p align="center">
    <img width="60%" src="images/cfb_d.png"> 
</p>


#### Ecuaciones

Si $i = 0$:

$$C_0 = E_K(IV) \oplus P_0$$

$$P_0 = E_K(IV) \oplus C_0$$

En otro caso:

$$C_i = E_K(C_{i - 1}) \oplus P_i$$

$$P_i = E_K(C_{i - 1}) \oplus C_i$$


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


### CTR (Counter)

El modo CTR es el modo más aceptado y usado en la actualidad. Se parte desde un $IV$ el cual es concatenado, sumado o operado con XOR con un contador. Este contador va aumentando en una unidad por cada bloque y es el bloque resultado de la encriptación $IV$ y contador el que se opera por XOR con el texto en claro.

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

$$C_i = E_K(IV + i) \oplus P_0$$

$$P_i = E_K(IV + i) \oplus C_0$$