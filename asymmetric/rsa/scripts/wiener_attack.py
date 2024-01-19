'''
Implementación del ataque Wiener.
 
Autor: Daysapro.
'''
 
 
from Crypto.Util.number import long_to_bytes, bytes_to_long
from continued_fraction import expansion, convergents
from sympy import Symbol, solve
 
n = 6727075990400738687345725133831068548505159909089226909308151105405617384093373931141833301653602476784414065504536979164089581789354173719785815972324079
e = 4805054278857670490961232238450763248932257077920876363791536503861155274352289134505009741863918247921515546177391127175463544741368225721957798416107743
secret = b"flag{wiener_attack}"
 
c = pow(bytes_to_long(secret), e, n)
print(f"Texto cifrado: {str(c)}")
 
 
a = expansion(e, n)
ks, ds = convergents(a)
 
for d,k in zip(ds, ks):
    if k == 0:
        continue
    phi = (e * d - 1) // k
    p = Symbol('p', integer=True)
    roots = solve(p**2 + (phi - n - 1) * p + n, p)
 
    if len(roots) != 0:
        d = pow(e, -1, phi)
        print(long_to_bytes(pow(c, d, n)))