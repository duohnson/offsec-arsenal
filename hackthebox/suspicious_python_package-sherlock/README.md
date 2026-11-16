### Hack The Box | Suspicious Python Package.

En este Sherlock nos dan un triage de una computadora donde un usuario instaló un paquete de Python y después alguien logró entrar a su cuenta. Vamos a revisar el historial del navegador, los archivos que dejó el paquete y los registros de NTFS para entender qué pasó.

El archivo que nos dan está en `C:\Users\LetsDefend\Desktop\ChallengeFile\MalPy.zip`. Al extraerlo encontramos los artefactos del usuario Administrator, incluyendo los datos de Chrome y el paquete sospechoso.

Primero vamos a revisar de dónde se descargó. Abrimos la base `History` de Chrome con DB Browser for SQLite y buscamos en la tabla `downloads_url_chains`.

```sql
SELECT * FROM downloads_url_chains;
```

De ahí encontramos que lo descargaron desde:

`https://github.com/0xMM0X/peloton`

En el historial también se ve el nombre del archivo: `peloton-main.zip`. El nombre y la versión del paquete salen de `PKG-INFO`:

```text
Name: peloton-client123
Version: 0.8.10
```

Para saber la hora exacta no usamos el download end time de Chrome. Parseamos el `$MFT` con MFTECmd y buscamos `peloton-main.zip`. La fecha `Created0x10` es **2024-01-22 20:00:11**.

Buscando qué archivo se ejecutó, encontramos en el historial de PowerShell que el usuario corrió `setup.py`. Al abrirlo vimos una cadena rara, invertida y comprimida/codificada en Base64. La pasamos por CyberChef hasta recuperar el contenido.

Ahí aparece lo que hacía el script: copiaba la base de datos de Chrome llamada `Login Data`, la metía dentro de `temp_file.zip`, la enviaba al C2 `172.31.78.151:8000` y luego borraba el zip. El archivo con el código malicioso entonces era `setup.py`.

Lo interesante es que no solo encontramos la lógica del robo, también hay que confirmar si el archivo temporal realmente se creó. Para eso parseamos el USN Journal `$J`:

```powershell
MFTECmd.exe -f .\$J --csv .\output --csvf usn.csv
```

Filtrando por `temp_file.zip` vemos varios registros de creación y borrado. Todos aparecen en el segundo **2024-01-22 20:00:42**, porque el archivo se creó y eliminó casi inmediatamente después de enviarlo.

El script apuntaba a `Login Data`, así que abrimos esa base de datos SQLite con DB Browser y revisamos la tabla `logins`. Encontramos una credencial guardada para `https://app.letsdefend.io/` con el usuario `all4m`.

Con esto ya podemos reconstruir el proceso: el usuario descargó el paquete desde GitHub, ejecutó el `setup.py`, el script copió la base de contraseñas de Chrome y la preparó para exfiltrarla a `172.31.78.151:8000`. Después eliminó el archivo temporal para no dejarlo en disco.

En esta investigación nos sirvió cada artefacto para una parte distinta: Chrome nos mostró la URL, `PKG-INFO` el nombre y versión, PowerShell qué archivo se ejecutó, `setup.py` lo que hacía, el `$J` confirmó el borrado y `Login Data` mostró cuál cuenta estaba expuesta.
