## Algoritmo Extendido de Euclides

## Se requieren minimo dos numeros para obtener su Maximo Común Divisor (MCD)
a  =0
b  =0
a = int(input("a: "))
b = int(input("b: "))

v = [a,b]
x = [1,0]
y = [0,1]
i = 1

while v[i] != 0:
    i = ((i + 1)%2)
    q = v[i] // v[(i + 1)%2]

    v[i] = v[i] - q * (v[(i + 1)%2])
    x[i] = x[i] - q * (x[(i + 1)%2])
    y[i] = y[i] - q * (y[(i + 1)%2])
i = ((i + 1)%2)
print(f"xi: {x[i]} --------- yi:{y[i]} ---------- vi: {v[i]}")
