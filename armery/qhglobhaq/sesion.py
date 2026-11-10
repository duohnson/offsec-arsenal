import sys, json, requests, urllib3, test
urllib3.disable_warnings()

H = "DOMAIN"
e1 = "ENDPOINT 1"
e2 = "ENDPOINT 2"
s = requests.Session(); s.verify = False

def verificar(au):
    s.post(f"{H}{e1}", json={"sku": "skull"})
    r = s.post(f"{H}{e2}", json={"raw": test.constructor(linea_usar=au)})
    print(r.status_code, r.text)

if __name__ == "__main__":
    verificar(sys.argv[1] if len(sys.argv) > 1 else "")
