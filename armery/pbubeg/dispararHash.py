#!/usr/bin/env python3
# uso: python3 term.py 'id'  |  python3 term.py --sh 'comando largo'
import sys, time, ssl, websocket

URL = "wss://nb-youhash.domain/terminal/ws"

def run(cmd, before=1.5, after=4.0):
    ws = websocket.create_connection(URL, timeout=10,
        header=["Authorization: Bearer x"],
        sslopt={"cert_reqs": ssl.CERT_NONE, "check_hostname": False})
    ws.settimeout(0.3)
    buf = []
    end = time.time() + before
    while time.time() < end:
        # drena el banner con tope de tiempo
        try:
            d = ws.recv()
            if d: buf.append(d)
        except Exception:
            pass
    ws.send(cmd + "\n")
    end = time.time() + after
    # lee la salida con tope de tiempo
    while time.time() < end:
        try:
            d = ws.recv()
            if d: buf.append(d)
        except Exception:
            pass
    try: ws.close()
    except Exception: pass
    out = "".join(x.decode("utf-8", "replace") if isinstance(x, bytes) else x for x in buf)
    return out

if __name__ == "__main__":
    cmd = " ".join(sys.argv[1:])
    print(run(cmd))
