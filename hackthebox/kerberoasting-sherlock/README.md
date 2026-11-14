### Hack The Box | Kerberoasting.

Sherlock: Active Directory / Análisis de eventos de Windows.

En este Sherlock nos dan una colección de triage del dominio `SOPRANOS.local`: logs de seguridad del Domain Controller y de la computadora Tony, el `$MFT` y la carpeta de tareas programadas. La contraseña del archivo `Kerberoasting.7z` es `infected`.

La alerta inicial era por Kerberoasting, pero al revisar los eventos también fui encontrando cómo se movió el atacante y qué dejó para mantener acceso. Trabajé principalmente con Event Log Explorer, MFTECmd y Timeline Explorer. Me ayudó ir separando la investigación por host: primero el Domain Controller para encontrar el ticket Kerberos, y después Tony para entender cómo había empezado el acceso a la estación.

## Buscando el Kerberoasting

Empecé por el Security log del Domain Controller y busqué el evento **4769**, que se genera cuando se solicita un ticket de servicio Kerberos. Había que tener cuidado porque este evento también aparece durante actividad normal, así que no asumí que cualquier 4769 era un ataque. Revisé quién solicitaba el ticket, cuál era el servicio, la dirección de origen y el tipo de cifrado.

La combinación que me llamó la atención fue una solicitud de un usuario normal para una cuenta de servicio cuyo nombre no terminaba en `$`, con `Ticket Encryption Type: 0x17`. Ese valor corresponde a RC4. Una solicitud así puede ser útil para Kerberoasting porque el atacante obtiene un ticket que puede intentar crackear fuera de línea. Esto no significa que el password ya esté crackeado; el evento muestra la solicitud del ticket y el riesgo asociado.

Encontré una solicitud que coincidía con esos datos. En los detalles vi que `tony@SOPRANOS.LOCAL` había pedido un ticket para el servicio `SQLService`. La IP aparecía como `::ffff:192.168.110.135` y el puerto de origen era `54348`, es decir, `192.168.110.135:54348`.

La hora en Event Log Explorer se mostraba en UTC+3. Convertí el timestamp del evento a UTC y el Kerberoasting ocurrió el **2024-09-17 00:59:53 UTC**. Del mismo evento anoté el origen `192.168.110.135:54348`, el usuario `tony@SOPRANOS.LOCAL` y el servicio `SQLService`. Tener todos esos datos juntos me permitió usar la IP como pivote en el resto de los logs.

La pista de RC4 me ayudó a entender por qué el evento era interesante: el ticket de servicio se puede solicitar y luego intentar crackear fuera de línea, sin tener que seguir probando contraseñas contra el servicio.

## Cuenta creada para persistencia

Después busqué el evento **4720**, que registra cuando se crea una cuenta. Cerca de la actividad del ataque encontré el usuario nuevo `whoisa1l4m`. Lo tomé como una pista de persistencia y quise comprobar si había algo más en los artefactos que apuntara a esa misma cuenta, en vez de quedarme solo con el evento de creación.

En la carpeta `C:\Windows\System32\Tasks` había una tarea con ese mismo nombre. Para encontrar cuándo se creó, parseé el `$MFT` con MFTECmd y revisé el resultado en Timeline Explorer:

```powershell
MFTECmd.exe -f '$MFT' --csv out
```

Al filtrar por `whoisa1l4m`, encontré la hora de creación del archivo de tarea: **2024-09-17 01:09:19**. El nombre de la tarea coincidía con la cuenta recién creada. Esa coincidencia, junto con la hora y el evento 4720, apunta a que la tarea programada se usó para mantener acceso. Es un buen ejemplo de por qué revisé tanto los eventos como los archivos: el log muestra la creación de la cuenta, mientras que el `$MFT` aporta la marca temporal del archivo de tarea.

Más tarde, el evento **4624** mostró un inicio de sesión exitoso con `whoisa1l4m` desde `192.168.110.135`, usando el puerto de origen `43516`.

## Revisando el primer acceso a Tony

Luego me fui al Security log de la estación Tony y busqué eventos desde `192.168.110.135`. El primer registro fue un inicio de sesión fallido, evento **4625**, a las **2024-09-14 05:08:20 UTC**. Para tener la hora correcta revisé `SystemTime` en el XML, porque la hora que muestra el visor estaba en UTC+3. El fallo por sí solo no demuestra que el acceso fuera exitoso, pero sirve para ubicar el primer contacto de esa IP con la estación y luego compararlo con los eventos posteriores.

En los eventos siguientes encontré un inicio de sesión desde esa misma IP usando la cuenta `Corrado` del dominio `SOPRANOS`. Eso muestra el acceso a Tony antes de que el atacante pidiera el ticket Kerberos con la cuenta `tony` y creara el usuario de persistencia. Me fijé en el host y la cuenta de cada evento para no mezclar ese acceso inicial a la workstation con la solicitud de ticket que aparece después en los logs del Domain Controller.

## La secuencia que pude reconstruir

Con los tiempos convertidos a UTC, la secuencia que pude reconstruir queda así:

| Hora UTC | Lo que encontré | Evidencia |
|---|---|---|
| 2024-09-14 05:08:20 | Primer intento desde `192.168.110.135` contra Tony | Security 4625 |
| Después del primer intento | Acceso a Tony usando `SOPRANOS\\Corrado` | Security log de Tony |
| 2024-09-17 00:59:53 | `tony` pide un ticket para `SQLService` con cifrado RC4 | Security 4769 del DC |
| 2024-09-17 01:09:19 | Se crea el archivo de tarea `whoisa1l4m` | `$MFT` y carpeta Tasks |
| Más adelante | Inicio de sesión exitoso con `whoisa1l4m` desde la IP sospechosa | Security 4624 |

El evento 4720 completa la parte de creación de la cuenta, mientras que el evento 4624 muestra que esa cuenta luego se utilizó para iniciar sesión desde `192.168.110.135`, por el puerto `43516`. Así pude conectar el ticket solicitado, la cuenta de persistencia y el acceso posterior, en vez de tratarlos como hallazgos sin relación.

Cuando analizo estos casos, intento no confiar en una sola marca de tiempo ni en un único evento. El visor presenta hora local, los eventos XML guardan `SystemTime` en UTC, y las marcas del `$MFT` tienen que compararse con la misma referencia temporal. Convertir todo a UTC antes de ordenar la secuencia me ayudó a no confundir el primer acceso del 14 de septiembre con el Kerberoasting y la persistencia del 17.

Este ejercicio me sirvió para practicar cómo distinguir un evento Kerberos sospechoso del ruido normal del Domain Controller. También vi que los eventos 4769, 4720, 4624 y 4625, combinados con el `$MFT` y la carpeta de tareas, ayudan a armar una línea de tiempo y relacionar el acceso inicial con la solicitud del ticket y la persistencia. La parte más importante para mí fue usar la IP `192.168.110.135` y los nombres de cuenta como pivotes, y luego validar cada paso en otra fuente antes de darlo por conectado.
