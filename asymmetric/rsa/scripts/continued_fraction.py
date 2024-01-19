'''
Calculadora de la expansión y coeficientes de un número en su forma de fracción continua.
 
Autor: Daysapro.
'''
 
 
def expansion(nominator, denominator):
    a = []
    residue = nominator % denominator
    a.append(nominator // denominator)
    while residue != 0:
        nominator = denominator
        denominator = residue
        residue = nominator % denominator
        a.append(nominator // denominator)
 
    return a
 
 
def convergents(a):
    nominators = []
    denominators = []
 
    for i in range(len(a)):
        if i == 0:
            nominators.append(a[i])
            denominators.append(1)
        elif i == 1:
            nominators.append(1 + a[i] * a[i - 1])
            denominators.append(a[i])
        else:
            nominators.append(nominators[i - 2] + a[i] * nominators[i - 1])
            denominators.append(denominators[i - 2] + a[i] * denominators[i - 1])
 
    return nominators, denominators
 
 
a = expansion(6379, 8927)
nominators, denominators = convergents(a)