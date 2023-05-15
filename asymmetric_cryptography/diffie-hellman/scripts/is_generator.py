'''
Calculadora de generadores del grupo multiplicativo de campos finitos de orden p.

No es una buena implementación, pero sí muy didáctica.

Aprovecha la propiedad de que un generador de un grupo multiplicativo finito es capaz de generar todos los elementos del grupo con sucesivas potencias sin repetir ninguno hasta generarlos todos.

Por ejemplo, suponiendo el grupo multiplicativo {1, 2, 3, 4, 5, 6}, sabemos que 3 es generador porque:
3**1 = 3
3**2 = 2
3**3 = 6
3**4 = 4
3**5 = 5
3**6 = 1

Se han generado todos los elementos del grupo sin repetición. En el caso del 4:
4**1 = 4
4**2 = 2
4**3 = 1
4**4 = 4

Se repite el 4 antes de generar el resto de elementos, por lo que 4 no sería generador del grupo.

Autor: Daysapro.
'''


def is_generator(g, p):
    generated = []
    for i in range(1, p):
        e = pow(g, i, p)
        if e in generated:
            return False
        else:
            generated.append(e)

    if len(generated) == p - 1:
        return True


p = 37
print("Los generadores de {p} son: ".format(p=p))
for g in range(p):
    if is_generator(g, p):
        print(g)