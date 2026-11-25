# maq por ssh entrar primero

python3 - <<'EOF'
import socket, os, array

name = "maq-nombre"

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(f"/run/{name}/mgmt.sock")

fds = array.array("i")
msg, anc, flags, addr = s.recvmsg(4096, socket.CMSG_SPACE(2 * fds.itemsize))
print("MSG:", msg.decode(errors="ignore"))

for level, ctype, data in anc:
    if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
        fds.frombytes(data[:len(data) - len(data) % fds.itemsize])
        for fd in fds:
            print(f"--- fd {fd} ---")
            print(os.read(fd, 4096).decode(errors="ignore"))
            os.close(fd)

s.close()
EOF
