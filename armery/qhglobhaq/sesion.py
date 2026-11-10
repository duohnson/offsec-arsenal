import sys, json, requests, urllib3, test
urllib3.disable_warnings()

H = "https://airsnacks.htb/"
s = requests.Session(); s.verify = False

def verificar(au):
    s.post(f"{H}/cart/add", json={"sku": "skull"})
    r = s.post(f"{H}/checkout/boarding-pass/verify", json={"raw": test.constructor(linea_usar=au)})
    print(r.status_code, r.text)

if __name__ == "__main__":
    verificar(sys.argv[1] if len(sys.argv) > 1 else "")
