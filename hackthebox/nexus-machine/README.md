### Hack The Box | Touch.

Se realiza primer scaneo con nmap:

- nmap -sC -sV ip

└─$ nmap -sC -sV 10.129.143.219     
Starting Nmap 7.99 ( https://nmap.org ) at 2026-11-01 18:20 -0500
Nmap scan report for nexus.htb (10.129.143.219)
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Nexus Energy Authority \xE2\x80\x94 Powering the Nation's Future
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.10 seconds

Donde se comprende que:

| Puerto | Servicio | Lectura |

| 22/tcp | ssh | Ubuntu y acceso remoto confirmado. |

| 80/tcp | http | Servicio web HTTP. |

### Entonces:

Se busca en la web y nos da un dominio http://nexus.htb/, tratando de recuperar información importante encontramos que el correo de un personal es: j.matthew@nexus.htb.

Ahora se utilizan sistemas de escaneo para ver subdominios, rutas conocidas, y ver que tipo de información podemos extraer.

Feroxbuster y Gobuster no arrojan ningun resultado util o usable.

Captura 1

Con FFUF si rastreamos subdominios, los cuales son git y billing.

Captura 2

Ingresamos a ambos.
En el billing hay un panel web con inicio de sesión.

Pero lo interesante viene realmente cuando abro el git.nexus.htb, que me aparece un git con exposicion de datos, pero aun sin credenciales.

Captura 3

Si descargamos ese git, y empezamos a analizarlo, damos con el resultado de un commit realizado, con el cual intentan borrar credenciales expuestas, sin embargo, ya se encontraba en un commit anterior que logramos recuperar.

Captura 4

┌──(kali㉿kali)-[~/pentest/machines/krayin-docker-setup]
└─$ sudo git diff 9b817fa 1615c46
diff --git a/.env b/.env
index 5ae1bb2..cb7ccc3 100644
--- a/.env
+++ b/.env
@@ -2,7 +2,7 @@ APP_NAME='Krayin CRM'
 APP_ENV=local
 APP_KEY=
 APP_DEBUG=true
-APP_URL=http://billing.nexus.htb
+APP_URL=http://nexus.htb
 APP_TIMEZONE=Asia/Kolkata
 APP_LOCALE=en
 APP_CURRENCY=USD
@@ -15,7 +15,7 @@ DB_HOST=krayin-mysql
 DB_PORT=3306
 DB_DATABASE=krayin
 DB_USERNAME=krayin
-DB_PASSWORD=
+DB_PASSWORD=N27xh!!2ucY04
 DB_PREFIX=
 BROADCAST_DRIVER=log
 CACHE_DRIVER=file

Probando estas credencianles en billing, logramos ingresar al panel.

Captura 5

Con estos datos nos damos cuenta que el servicio http, podria aceptar quizas extensiones php, intentaremos ver si en My Account, permite subir un archivo que no sea imagen.

Captura 6

No funciono como esperabamos.
