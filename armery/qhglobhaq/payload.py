#!/usr/bin/env python3

from enum import unique
import sys

def fil(s, n):
    return (str(s) + " " * n)[:n]

def constructor(linea_usar=" ", tarea="AC", version="5",
    nombre="DESMARCAR/LUC", pnr="ABC123", frm="YUL", to="CRC",
    corredor="AC", volador="0834", dato="326", compositor="J",
    seteo="001A", seq="0025", estado="1"):
        mandar = "M1" + fil(nombre, 20) + "E" + fil(pnr, 7)
        mandar += fil(frm, 3) + fil(to ,3) + fil(corredor, 3)
        mandar += fil(volador, 5) + fil(dato, 3) + compositor + fil(seteo, 4)
        mandar += fil(seq, 5) + estado
        assert len(mandar) == 58, len(mandar)

        unique = "0" + "O" + "O" + "6225" + "B" + fil(tarea, 3) + fil("", 13)
        repetir = fil("014", 3) + fil("1234567890", 10) + " " + "0"
        repetir += fil(corredor, 3) + fil(corredor, 3) + fil("", 16) + " "
        repetir += fil("", 3) + "0"

        var = ">" + version + ("%02X" % len(unique)) + unique + ("%02X" % len(repetir)) + repetir + linea_usar
        return mandar + ("%02X" % len(var)) + var

if __name__ == "__main__":
    sys.stdout.write(constructor(linea_usar=sys.argv[1] if len(sys.argv) > 1 else ""))
