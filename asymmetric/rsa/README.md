# RSA

[![development_tag](https://img.shields.io/badge/en%20desarrollo-10%25-brightgreen)]()

[![follow_tag](https://img.shields.io/github/followers/Daysapro?label=Seguir&style=social)](https://github.com/Daysapro) [![like_tag](https://img.shields.io/github/stars/Daysapro/cryptonomicon?label=Favorito&style=social)](https://github.com/Daysapro/cryptonomicon)

[![public_key_tag](https://img.shields.io/:clave%20pública-2ecc71.svg?labelColor=FF0000&color=FF0000)]() [![modular_arithmetic_tag](https://img.shields.io/:aritmética%20modular-2ecc71.svg?labelColor=149AFF&color=149AFF)]() [![algebra_tag](https://img.shields.io/:álgebra-2ecc71.svg?labelColor=149AFF&color=149AFF)]()


> El problema de factorización de números enteros.

RSA es un sistema criptográfico descrito en 1979 por [Ron Rivest](https://en.wikipedia.org/wiki/Ron_Rivest), [Adi Shamir](https://en.wikipedia.org/wiki/Adi_Shamir) y [Leonard Adleman](https://en.wikipedia.org/wiki/Leonard_Adleman), quienes forman con sus apellidos el nombre del sistema. Una noche de abril de 1977 Rivest llegó a su casa después de haber celebrado la festividad judía Pésaj con algunos estudiantes del instituto de tecnología de Massachusetts. Sin poder dormir se puso a pensar sobre su [función unidireccional](https://en.wikipedia.org/wiki/One-way_function), idea que intentaba desarrollar con sus compañeros Shamir y Adleman estos últimos meses. Pasó toda la noche formalizando la idea y al día siguiente terminaba un primer [boceto](https://web.archive.org/web/20230127011251/http://people.csail.mit.edu/rivest/Rsapaper.pdf) de lo que años después sería el sistema RSA.

Los primeros años el cifrado pasó desapercibido. El coste de implementarlo era demasiado alto para los ordenadores de la época. El sistema además estaba clasificado como confidencial y hasta 1997 no fue accesible al público, momento en el que con los avances tecnológicos era más razonable valorar su uso.


## Requisitos

Para poder entender el sistema RSA se recomienda al lector tener conocimientos básicos de cálculo, aritmética modular y de álgebra. Además, es importante destacar que los ejemplos proporcionados están desarrollados en el lenguaje de programación Python, por lo que para el aprovechamiento total del contenido se recomienda conocer un poco de dicho lenguaje.


## Índice

1. [Introducción](#introducción)
2. [Generación de claves](#generación-de-claves)
3. [Cifrado y descifrado](#cifrado-y-descifrado)
4. [Criptoanálisis](#criptoanálisis)
   1. [Clave pública y privada](#clave-pública-y-privada)
       1. [Raíz cúbica](#raíz-cúbica)
       2. [Hastad's Broadcast Attack](#hastads-broadcast-attack)
       3. [Wiener's attack](#wieners-attack)
           1. [Fracciones continuas](#fracciones-continuas)
           2. [Comprobación del candidato](#comprobación-del-candidato)
           3. [Ejemplo numérico](#ejemplo-numérico)


## Introducción

Se trata de un cifrado asimétrico, por lo que cada parte de la comunicación posee una clave pública con su respectiva clave privada. 

Se considera que RSA es un cifrado relativamente lento. Actualmente, más que para cifrar y descifrar información cotidiana, se utiliza para enviar claves de cifrados simétricos.

El punto de partida para generar las claves es la generación de dos primos lo suficientemente grandes y el cálculo del valor $n$, producto de ellos. Este valor es público y la seguridad de RSA depende de la dificultad práctica de factorizar este valor. Este problema matemático se denomina el problema de factorización de números enteros. 

A día de hoy no se conocen métodos que solvente este problema en enteros muy grandes sin factores pequeños.


## Generación de claves

Las claves se generan según los siguientes pasos:

1. Se eligen dos primos grandes $p$ y $q$. Se recomienda que sean primos generados aleatoriamente y con una gran diferencia entre ellos. Estos primos son privados.

2. Se calcula $n = p \cdot q$. Este valor es el módulo sobre el que se realizan las operaciones de cifrado y descifrado.

3. Se computa la [función de Carmichael](https://es.wikipedia.org/wiki/Funci%C3%B3n_de_Carmichael) $\lambda(n)$. Esta función representa el entero positivo más pequeño que cumple:

$$a^m \equiv 1 \bmod n$$

Para todo entero $a$ coprimo a $n$. Siendo $n = p \cdot q$ y $p$ y $q$ primos, la función $\lambda(n) = lcm(\lambda(p), \lambda(q))$. Por el [pequeño teorema de Fermat](https://en.wikipedia.org/wiki/Fermat%27s_little_theorem), la función de Carmichael de un primo equivale a la [función de Euler](https://en.wikipedia.org/wiki/Euler%27s_totient_function), siendo $\lambda(p) = \phi(p) = p - 1$.

$$\lambda(n) = lcm(\phi(p),\phi(q)) = lcm((p - 1),(q - 1))$$

Se desarrolla el mínimo común múltiplo:

$$\lambda(n) = lcm((p - 1),(q - 1)) = \frac{|(p - 1) \cdot (q - 1)|}{gcd((p - 1),(q - 1))}$$

En el artículo original de RSA se utiliza la función de Euler $\phi(n) = (p - 1) \cdot (q - 1)$ en vez de la función de Carmichael. Esta función representa la cantidad de números enteros positivos menores de $n$ que son coprimos a $n$. Las congruencias que se van a exponer a continuación también se cumplen con la función de Euler ya que esta es siempre divisible entre $\lambda(n)$.

4. Se elige un entero $e$ en el intervalo $2 < e < \lambda(n)$ siendo coprimo con $\lambda(n)$. El valor elegido más común es $2^{16} + 1 = 65537$.

5. Se determina $d \equiv e^{-1} \bmod \lambda(n)$, siendo $d$ el inverso modular multiplicativo de $e$ módulo $\lambda(n)$.

Así, la clave pública está constituida por el par $(e, n)$, mientras que la clave privada es el valor $d$. $\lambda(n)$, $p$ y $q$ deben mantenerse en secreto al igual que $d$, porque permiten su cálculo.


## Cifrado y descifrado

Alicia quiere enviarle a Bob un mensaje $M$. Para empezar, convierte este mensaje en bruto $M$ en un entero $m$ según un protocolo reversible conocido como [esquema de relleno](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Padding_schemes). Una vez preparado el mensaje, toma la clave pública de Bob $(e, n)$ y calcula: 

$$c \equiv m^e \bmod n$$

Este valor es el mensaje cifrado que envía a Bob.

Bob, único conocedor del valor $d$ tal que $e \cdot d \bmod \lambda(n)$, recupera $m$ como:

$$m \equiv c^d \bmod n$$

Desde $m$, con el esquema de relleno utilizado, Bob recupera $M$.


## Esquema de relleno

Por razones de seguridad es recomendable el uso de un esquema de relleno en el sistema RSA. Este relleno es un valor aleatorio que se añade al mensaje $m$ antes de ser encriptado. De esta manera un desarrollador se asegura que $m$ no es un mensaje inseguro que pueda comprometer la seguridad.


## Criptoanálisis

A continuación se tratan los ataques más conocidos al sistema RSA relacionados con debilidades matemáticas debidas a una mala implementación del sistema.

Se dividen en vulnerabilidades relacionadas con las claves y otras relacionadas con los primos elegidos, que permitirán la factorización de $n$.


### Clave pública y privada

No se subdivide entre ataques a la clave pública y ataques a la clave privada por la relación que tiene una respecto a otra, siendo una el inverso modular multiplicativo de la otra en $\lambda(n)$. La mala elección de una afecta a la otra y a la seguridad del sistema directamente.


#### Raíz cúbica

Siendo $e = 3$ y $m$ un mensaje sin relleno lo suficientemente pequeño para $m^e < n$:

$$c \equiv m^3 \bmod n = m^3$$

El módulo pierde su significancia y el mensaje en claro es la raíz cúbica del texto cifrado.

$$m = \sqrt[3]{c}$$

Este ataque se puede generalizar para cualquier $e$ siempre que $m^e < n$, aunque el caso más común es $e = 3$.

> [Ver implementación del ataque de la raíz cúbica cuando e = 3.](scripts/cube_root.py)


#### Hastad's Broadcast Attack

Alicia quiere enviar el mismo mensaje a $k$ personas, las cuales comparten la clave pública $e$ y difieren en módulo $n$. Alicia tiene $k$ claves públicas $(e, n_i)$ y envía los textos cifrados $c_i$:

$$c_1 \equiv m^e \bmod n_1$$

$$c_2 \equiv m^e \bmod n_2$$

$$c_3 \equiv m^e \bmod n_3$$

Este ataque es posible en el momento que $k \geq e$.

Por ejemplo, si $e = 3$:

$$c_1 \equiv m^3 \bmod n_1 \rightarrow m^3 \equiv c_1 \bmod n_1$$

$$c_2 \equiv m^3 \bmod n_2 \rightarrow m^3 \equiv c_2 \bmod n_2$$

$$c_3 \equiv m^3 \bmod n_3 \rightarrow m^3 \equiv c_3 \bmod n_3$$

Según el [teorema chino del resto](https://en.wikipedia.org/wiki/Chinese_remainder_theorem), se puede encontrar una única solución de $m^3$:

$$m^3 \equiv \sum_{i = 1}^{3} c_i \cdot b_i \cdot b_i^{\prime} \bmod N$$

Siendo $b_i = \frac{N}{n_i}$, $b_i^{\prime} \equiv b_i^{-1} \bmod n_i$ y $N = n_1 \cdot n_2 \cdot n_3$.

> [Ver implementación del ataque Hastad's Broadcast.](scripts/hastad_broadcast_attack.py)


#### Wiener's Attack

Una clave privada $d$ pequeña podría acelerar el proceso de descifrado en el sistema RSA, aunque por razones de seguridad no es una buena opción. De hecho, el criptólogo Michael J. Wiener demostró que el sistema era vulnerable cuando $d < \frac{1}{3}n^{\frac{1}{4}}$.

Se sabe que:

$$e \cdot d \equiv 1 \bmod \phi(n)$$

Por tanto, existe un valor $k$ tal que:

$$e \cdot d - k \cdot \phi(n) = 1$$

Dividiendo entre $d \cdot \phi(n)$:

$$\frac{e}{\phi(n)} - \frac{k}{d} = \frac{1}{d \cdot \phi(n)}$$

$d \cdot \phi(n)$ es un valor muy pequeño que tiende a 0, por lo que:

$$\frac{e}{\phi(n)} \approx \frac{k}{d}$$

En base a estas ideas, Wiener formuló el siguiente teorema:

Siendo $n = p \cdot q$ con $q < p < 2p$ y $d < \frac{1}{3}n^{\frac{1}{4}}$, dada una clave pública $(e, n)$ un ataque puede recuperar eligiendo el correcto $\frac{k}{d}$ entre los valores [convergentes](https://en.wikipedia.org/wiki/Continued_fraction) de $\frac{e}{n}$.

Con estas condiciones, Wiener probaba que $\phi(n) \approx n$.


##### Fracciones continuas

El concepto de fracción continua surge a raíz de la necesidad de expresar cualquier número racional de una forma matemáticamente elegante.

Cualquier número se puede expresar según la siguiente fórmula:

$$x = a_0 + \frac{1}{a_1 + \frac{1}{a_2 + \frac{1}{a_3 + \frac{1}{...}}}}$$

Valorando el vector $a = [a_0, a_1, a_2, ..., a_i]$:

$$c_0 = a_0$$

$$c_1 = a_0 + \frac{1}{a_1}$$

$$c_2 = a_0 + \frac{1}{a_1 + \frac{1}{a_2}}$$

El vector de coeficientes $c = [c_0, c_1, c_2, ..., c_i]$ está formado por los que se llaman los valores convergentes de $x$.

Cada valor convergente de $\frac{e}{n}$ es un candidato a ser $\frac{k}{d}$.


##### Comprobación del candidato

Una vez obtenidos los valores convergentes de $\frac{e}{n}$ se debe comprobar cuál corresponde al valor $\frac{k}{d}$ real.

Desde:

$$\phi(n) = (p - 1) \cdot (q - 1)$$

$$\phi(n) = p \cdot q - p - q + 1 = n - p - \frac{n}{p} + 1$$

Multiplicando por $p$:

$$p^2 + p \cdot (\phi(n) - n - 1) + n = 0$$

Y habiendo obtenido desde las convergencias un conjunto de $k$ y $d$:

$$\phi(n) = \frac{e \cdot d - 1}{k}$$

$$p^2 + p \cdot (\frac{e \cdot d - 1}{k} - n - 1) + n = 0$$

Se obtienen los valores de $p$ y $q$ que pueden ser o no válidos.


##### Ejemplo numérico

Teniendo la clave pública $e = 8737$ y $n = 8927$.

$$\frac{e}{n} = \frac{8737}{8927} = \frac{1}{1 + \frac{1}{45 + \frac{1}{1 + ...}}}$$

$$a = [0, 1, 45, 1, 62, 3]$$

$$c_0 = 0$$

$$c_1 = 0 + \frac{1}{1} = 1$$

$$c_2 = 0 + \frac{1}{1 + \frac{1}{45}} = \frac{45}{46}$$

$$c_3 = 0 + \frac{1}{1 + \frac{1}{45 + \frac{1}{1}}} = \frac{46}{47}$$

$$c = [0, \frac{1}{1}, \frac{45}{46}, \frac{46}{47}, \frac{2897}{2960}, \frac{8737}{8927}]$$

Nótese que, a nivel matemático, los coeficientes de convergencia tienden en decimal al valor original.

$$\frac{e}{n} = \frac{8737}{8927} \approx 0.978716$$

$$c = [0, 1, 0.978261, 0.978723, 0.978716, 0.978716]$$

Para estos cálculos, se ha utilizado un algoritmo implementado en Python.

> [Ver calculadora de la expansión y coeficientes de un número en su forma de fracción continua.](scripts/continued_fraction.py)

Se calculan las funciones de Euler candidatas siendo $k$ los numeradores y $d$ los denominadores.

$$\phi(n)_i = \frac{e \cdot d_i - 1}{k_i}$$

Por ejemplo, la función para $k = 1$ y $d = 1$:

$$\phi(n)_1 = \frac{8737 \cdot 1 - 1}{1} = 8736$$

$$p_1^2 + p_1 \cdot (\phi(n) - n - 1) + n = 0$$

$$p_1^2 + p_1 \cdot (8736 - 8927 - 1) + 8927 = 0$$

$$p_1^2 - 192p_1 + 8927 = 0$$

Las raíces son $113$ y $79$. Fácilmente se ve que $113 \cdot 79 = 8927 = n$.

> [Ver implementación del ataque Wiener.](scripts/wiener_attack.py)