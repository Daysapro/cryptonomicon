'''
Graficador de n valores de a**x = b mod m.

Cambiar valores de a, m y n. Recomiendo probar a y m grandes.

Autor: Daysapro.
'''


import matplotlib.pyplot as plt


a = 100
m = 191
n = 100

x = []
b = []

for i in range(n):
    x.append(i)
    b.append(pow(a, i, m))

plt.plot(x, b, "o", color="black")

plt.xlabel("x")
plt.ylabel("b")

plt.savefig("dlog.png", dpi=1200)