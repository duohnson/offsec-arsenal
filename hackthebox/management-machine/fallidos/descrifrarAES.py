import base64, ssl, urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ctx = ssl._create_unverified_context()
raw = base64.b64decode(urllib.request.urlopen("https://management.htb/assets/app.enc", context=ctx).read().strip())
key = base64.b64decode("C+XDTUB0EuPY7BE+xzRcMP6dNjWd0h0GPxdt8tWSTVY=")
open("app.js","wb").write(AESGCM(key).decrypt(raw[:12], raw[12:], None))
