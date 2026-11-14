### Hack The Box | PurpleKnight.

Sherlock: Active Directory.

En este Sherlock nos dan acceso a un dominio de Active Directory y la herramienta Purple Knight para revisar qué cosas están mal configuradas. No es como las otras máquinas donde uno empieza con nmap y busca por dónde entrar; aquí la idea es revisar el reporte y arreglar los problemas que va encontrando.

Primero me conecté por RDP. Como estoy usando Linux, abrí la sesión con `xfreerdp`. Ya dentro de la máquina busqué Purple Knight y lo ejecuté como administrador. La contraseña que pide es `H4ck_The_Blue_!`.

Acepté la licencia, escogí el análisis de Active Directory y seleccioné el bosque `forela.local`. Marqué todos los indicadores y dejé que terminara el escaneo. En esta versión decía que había 119 indicadores, pero solo evaluó 116 porque tres no aplicaban al entorno.

Cuando terminó, abrí el reporte. Al inicio salen los hallazgos por severidad. Me fui metiendo en cada uno para ver qué cuentas estaban involucradas y qué recomendaba Purple Knight. El puntaje puede cambiar un poco, pero estos fueron los problemas que aparecieron:

- **Critical:** usuarios privilegiados con contraseñas débiles y un grupo con permisos DCSync.
- **High:** LDAP signing desactivado, cuentas privilegiadas con contraseña que nunca expira y cuentas privilegiadas con SPN.
- **Medium:** delegación sin restricciones, no se usan gMSA, SPN que todavía usan RC4 y una cuenta sin Kerberos pre-authentication.
- **Low:** los usuarios normales pueden agregar equipos al dominio y hay más cuentas con SPN.

## Lo que fui revisando

### Política de contraseñas

Una de las primeras preguntas era cuántos usuarios salían con la política débil. En el hallazgo vi que eran **4 usuarios privilegiados**.

Después tocaba crear una política con mínimo de 15 caracteres para `Domain Users`. Estuve viendo las opciones del Active Directory Admin Center, en `System > Password Settings Container`, donde se crea un Password Settings Object. También se puede hacer por PowerShell. La idea es crear la política y luego asignarla al grupo:

```powershell
New-ADFineGrainedPasswordPolicy -Name "15_Char_Baseline" `
    -Precedence 1 `
    -MinPasswordLength 15

Add-ADFineGrainedPasswordPolicySubject -Identity "15_Char_Baseline" `
    -Subjects "Domain Users"
```

En otro hallazgo vi cuentas con la opción **Password never expires**. Al principio parece que solo hay que cambiar las cuentas que muestra el reporte, pero también hay que revisar el Administrator integrado. Para encontrar las cuentas habilitadas que tienen esa opción:

```powershell
Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} |
    Select Name
```

Y para quitarla:

```powershell
Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} |
    Set-ADUser -PasswordNeverExpires $false
```

### LDAP signing

El siguiente hallazgo decía que los Domain Controllers no requerían LDAP signing. Estuve leyendo el detalle y menciona el riesgo de relay: si LDAP acepta conexiones sin firma, se puede abusar de autenticaciones NTLM que terminan llegando al controlador de dominio.

Para cambiarlo abrí `gpmc.msc` y edité **Default Domain Controllers Policy**. La opción está en:

`Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Domain controller: LDAP server signing requirements`

Ahí se cambia a **Require signing**. La política puede tardar en aplicarse; desde el DC se puede forzar con:

```powershell
Invoke-Command -ComputerName DC01 -ScriptBlock { gpupdate /force }
```

Una pregunta del reporte también pedía la primera táctica MITRE ATT&CK que aparece para este hallazgo. Revisando esa sección, la respuesta era **Privilege Escalation**.

### Usuarios que pueden agregar equipos

El reporte apuntaba al atributo `ms-DS-MachineAccountQuota`. Aprendí que este valor controla cuántas cuentas de equipo puede crear un usuario normal en el dominio. En este caso lo dejamos en cero:

```powershell
$DomainDN = (Get-ADDomain).DistinguishedName
Set-ADDomain -Identity $DomainDN -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

También se puede llegar al atributo desde las propiedades del dominio en Active Directory Users and Computers, activando **Advanced Features** y usando la pestaña **Attribute Editor**.

### SPN, Kerberoasting y gMSA

Revisando los SPN encontré que `Administrator` tenía `BackupSvc/DC01.forela.local`. La pregunta del Sherlock era identificarlo, pero en la remediación también había que quitarlo porque no debería estar puesto en una cuenta privilegiada.

El hallazgo también tenía `svc_iis` con el SPN `HTTP/web.forela.local`. En vez de dejar el servicio usando esa cuenta, lo pasé a una gMSA. La cuenta de equipo autorizada a recuperar la contraseña es `WEBSERVER01$`:

```powershell
Set-ADUser -Identity "Administrator" -ServicePrincipalNames `
    @{Remove="BackupSvc/DC01.forela.local"}

Set-ADUser -Identity "svc_iis" -ServicePrincipalNames `
    @{Remove="HTTP/web.forela.local"}

New-ADServiceAccount -Name "gmsa_iis" `
    -DNSHostName "web.forela.local" `
    -PrincipalsAllowedToRetrieveManagedPassword "WEBSERVER01$" `
    -ServicePrincipalNames "HTTP/web.forela.local"
```

La otra cuenta era `svc_sql`, que tenía que usar cifrado AES. Purple Knight mostraba **3 SPN** que soportaban RC4. Para habilitar AES-128 y AES-256 en `svc_sql`:

```powershell
Set-ADUser -Identity "svc_sql" `
    -Replace @{'msDS-SupportedEncryptionTypes' = 24}
```

El `24` es la suma de `8` para AES-128 y `16` para AES-256. También aprendí que gMSA se introdujo en Windows Server 2016 y que sirve para que Windows administre y rote la contraseña de una cuenta de servicio.

### Kerberos pre-authentication

La cuenta `svc_backup` tenía desactivada la preautenticación de Kerberos. Esto la hace vulnerable a **AS-REP Roasting**: un usuario puede pedir la respuesta de autenticación y tratar de crackearla fuera de línea.

Para corregirlo volví a requerir la preautenticación:

```powershell
Set-ADAccountControl -Identity "svc_backup" -DoesNotRequirePreAuth $false
```

### Delegación

También apareció `WEBSERVER01` con delegación sin restricciones. Estuve leyendo que un servidor así puede guardar tickets Kerberos de quienes se autentican; si alguien compromete el servidor, esos tickets pueden servir para suplantar usuarios.

La tarea pedía dejar la delegación limitada al servicio `MSSQLSvc/db.forela.local:1433`. Primero quité la delegación sin restricciones y después agregué ese servicio:

```powershell
Set-ADComputer -Identity "WEBSERVER01" -TrustedForDelegation $false
Set-ADComputer -Identity "WEBSERVER01" `
    -Add @{'msDS-AllowedToDelegateTo'="MSSQLSvc/db.forela.local:1433"}
```

La cuenta que tenía el SPN de MSSQL era `svc_sql`. La delegación restringida reduce lo que se puede delegar, pero igual hay que revisar bien qué servicio se permite.

### Permisos DCSync

El hallazgo crítico de DCSync señalaba al grupo `FORELA\Auditors`. Al revisar el reporte entendí que el grupo tenía permisos de replicación del dominio. Con esos permisos se pueden pedir hashes de cuentas como si uno fuera un Domain Controller, así que no es un permiso para dejar en un grupo cualquiera.

Abrí las propiedades del dominio, fui a **Security** y quité a `Auditors` estos permisos:

- `Replicating Directory Changes`
- `Replicating Directory Changes All`

## Al terminar

Cada vez que corregía un hallazgo esperaba un poco y revisaba el escritorio, porque ahí aparece la flag de la tarea. Algunas cosas tardan en reflejarse, sobre todo cuando dependen de Group Policy. Al final se puede correr Purple Knight otra vez para comparar el reporte y ver cómo mejoró el entorno.

Me quedó más claro que no todo es encontrar una vulnerabilidad para entrar: muchas veces el problema está en permisos o configuraciones que se fueron dejando así. También aprendí a fijarme en el objeto exacto que marca el reporte antes de cambiar cosas en Active Directory.
