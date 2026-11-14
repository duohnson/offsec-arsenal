### Hack The Box | NTLM Relay.

Sherlock: Network Forensics / Active Directory.

En este Sherlock nos dan una captura de red y el `Security.evtx` de una máquina llamada `Tony.SOPRANOS.local`. La alerta era por tráfico raro dentro de la red y la idea era reconstruir si alguien estaba escaneando otros equipos y haciendo un NTLM relay.

NTLM Relay es una técnica de ataque utilizada en redes Windows que permite a un atacante capturar una autenticación NTLM de un usuario y reenviarla a otro servicio para autenticarse haciéndose pasar por esa víctima, sin necesidad de conocer su contraseña.

Para extraer los archivos, el comprimido `NTLM-Relay.7z` usa la contraseña `infected`. Empecé abriendo la captura en Wireshark y después fui contrastando lo que veía con los eventos de seguridad de Windows.

## Buscando el equipo sospechoso

Primero filtré por `nbns` para ver qué equipos anunciaban su nombre NetBIOS. La mayoría se identificaba de forma normal, pero `192.168.110.135` mandaba consultas `NBSTAT` a otros hosts y no registraba un nombre propio. Eso me pareció raro, como un equipo haciendo reconocimiento en la red.

La primera consulta de esa IP fue el **2024-09-14 05:04:11**. Revisando los registros NBNS de `192.168.110.148`, encontré el nombre `TONY`, que corresponde al equipo afectado.

## Siguiendo la autenticación NTLM

Después filtré por `ntlmssp` y revisé las sesiones SMB. En los mensajes de autenticación aparecía `SOPRANOS\Corrado`, así que el dominio era `SOPRANOS` y la cuenta cuyas credenciales estaban siendo reutilizadas era `CORRADO`.

En la captura se veían los mensajes `NTLMSSP_NEGOTIATE`, `NTLMSSP_CHALLENGE` y `NTLMSSP_AUTH`. Eso me ayudó a entender el flujo del challenge-response y a reconocer que la autenticación estaba usando **NTLMSSP**. La cuenta no necesariamente tiene su hash crackeado: lo que vemos es que el atacante captura o hace relay de la autenticación para usarla contra otro servicio.

## Confirmando el acceso en Windows

Luego abrí `Security.evtx` en Event Log Explorer y busqué eventos **4624** (logon exitoso) y **4625** (logon fallido). En el evento 4624 originado desde `192.168.110.135` encontré estos datos:

- Cuenta: `CORRADO`
- Puerto de origen: `54414`
- Logon ID: `0x33ae9b`
- Hora UTC: `2024-09-14 05:19:39`

Antes de ese inicio de sesión exitoso había **6 eventos 4625** para Corrado. Para asegurarme de la hora, revisé el XML del evento y usé el valor `SystemTime`, porque el visor puede mostrar la fecha en la zona horaria local.

## Qué hizo después de autenticarse

Volví a la captura y seguí el tráfico SMB desde la IP sospechosa. Vi acceso remoto al registro por el named pipe `winreg`, usando operaciones como `OpenHKLM` y `OpenKey`. Una de las claves abiertas fue:

`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\JD`

La encontré relevante porque forma parte del material asociado al SysKey que protege credenciales almacenadas.

También observé que el atacante intentó conectarse al recurso administrativo:

`\\192.168.110.148\ADMIN$`

Durante la actividad apareció una solicitud SMB para crear el archivo temporal `FBcANENg.tmp`.

## Cómo entendí el ataque

La secuencia que armé fue: `192.168.110.135` empieza preguntando por equipos con NBNS, luego participa en autenticaciones NTLMSSP de la cuenta `SOPRANOS\Corrado`, y consigue que una autenticación llegue al equipo `TONY`. El evento 4624 confirma el inicio de sesión de red. Después, el tráfico SMB muestra acceso a `ADMIN$` y al registro remoto mediante `winreg`.

Este comportamiento se relaciona con **Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay**, MITRE ATT&CK `T1557.001`. Lo que más me ayudó fue combinar la captura con el log de Windows: Wireshark me mostró el recorrido por la red y el evento 4624 confirmó qué cuenta terminó iniciando sesión en el host.
