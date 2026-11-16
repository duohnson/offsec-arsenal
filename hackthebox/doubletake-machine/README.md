### Hack The Box | DoubleTake.

Se realizan primeros escaneos:

```bash
nmap -p- --min-rate=2000 -T4 10.129.234.54
nmap -p22,80 -sC -sV 10.129.234.54
```

Encontramos SSH en el puerto 22 y una web en el 80. La web pide Basic Auth con realm `Zentara`, asi que sin credenciales no podemos hacer mucho por ahi todavia.

El SSH muestra OpenSSH 10.6. Buscando un poco vemos que el servidor corre sobre Alpine Linux, que usa musl en vez de glibc. La version del laboratorio es vulnerable a un bypass de password de OpenSSH/musl.

La cuenta `alpine` tiene `*` en `/etc/shadow`, que normalmente significa que no puede iniciar sesion con password. El problema es que cuando mandamos una contraseña muy larga (300 caracteres), `crypt()` de musl falla y devuelve `*`. OpenSSH compara ese resultado con el valor que ya estaba en shadow y termina aceptando la contraseña.

Hay un detalle: se hace con dos intentos en la misma conexion. El primero falla pero guarda el salt, y en el segundo vuelve a leer el valor de la cuenta y la comparacion funciona. Con el script en Paramiko conseguimos ejecutar un comando y recibir una reverse shell como `alpine`.

```text
id
uid=1000(alpine) gid=1000(alpine) groups=1000(alpine)
```

Al revisar el sistema vemos `/.dockerenv`, entonces estamos dentro del contenedor y aun falta llegar al host.

En el home de `alpine` buscamos los perfiles del navegador y aparece `logins.json`:

```bash
find ~ -name logins.json
cat ~/.mozilla/firefox/zentara.default/logins.json
```

El archivo tiene credenciales para `http://172.17.0.1`, que es el gateway del contenedor y apunta al host. El campo `encType` vale `0`, por eso los valores solo estan en Base64, no protegidos con una master password.

```bash
echo Ym9i | base64 -d
echo Q29ycmVjdEhvcnNlQmF0dGVyeVN0YXBsZQ== | base64 -d
```

Sacamos el usuario `bob` y su password. Probamos esas credenciales por SSH y entramos como bob. Desde ahi leemos `user.txt`.

Con bob entramos a la web y revisamos la plataforma de chat. En la parte de conversaciones aparece una que habla del proceso de deploy. Tambien miramos las paginas Status y Deploy.

La pagina Deploy acepta archivos `.tar`, `.tar.gz` y `.tar.xz`, y deja indicar la ruta donde se van a extraer. Hay una nota que dice que el container engine descomprime los archivos del lado del servidor. Ahi es donde nos ponemos a revisar como Docker procesa los archivos.

La aplicacion termina llamando al Docker API `PUT /containers/{id}/archive`. En esta version Docker resuelve el binario de descompresion desde el overlay del contenedor. Si reemplazamos `/usr/bin/xz` por nuestro propio binario y despues subimos un tar.xz, el daemon ejecuta ese `xz` con privilegios de root del host.

Preparamos un programa en C que monta `/proc`, hace chroot a `/proc/1/root` (el filesystem del host) y ejecuta una reverse shell. Lo compilamos estatico y lo ponemos en la ruta que Docker va a buscar:

```bash
gcc -static -o xz xz.c
mkdir -p pkg/usr/bin
cp xz pkg/usr/bin/xz
cd pkg && tar cf ../plant.tar usr/bin/xz
```

Al inicio probamos subirlo desde Files, pero no funciona. Tenemos que usar el endpoint de Deploy, que es el que manda el archivo al Docker API:

```bash
curl -u 'bob:<password>' \
  -F 'archive=@plant.tar' \
  -F 'workspace=/' \
  http://10.129.234.54/deploy
```

Con esto se reemplaza el `/usr/bin/xz` dentro del contenedor. Ahora creamos un tar.xz normal y lo volvemos a subir desde Deploy. El Docker daemon detecta que tiene que descomprimirlo y ejecuta el xz que pusimos antes.

La pagina devuelve error 500, pero no quiere decir que haya fallado: nuestro programa se queda tratando de abrir la reverse shell hasta que la petición da timeout. Revisamos el listener y ya tenemos una shell como root del host.

```text
id
uid=0(root) gid=0(root) groups=0(root)
```

### HackTheBox Finalizada!!
