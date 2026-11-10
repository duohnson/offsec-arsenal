
import subprocess

comandos = [
    "id",
    "hostname",
    "dpkg -l | grep -i packagekit",
    "apt-mark showhold",
    "which pkcon packagekitd",
    "sudo -l",
    "find / -perm -4000 -type f 2>/dev/null | grep -vE '^/(usr/(bin|sbin)|bin|sbin)/'",
    "ls -la /var/www/machine_name /opt /home/user_name 2>/dev/null",
    "cat /etc/crontab; ls -la /etc/cron.d 2>/dev/null",
    "ps aux | grep -i user_name"
]

for comando in comandos:
    print("\n" + "=" * 60)
    print("COMANDO:", comando)
    print("=" * 60)

    resultado = subprocess.run(
        comando,
        shell=True,
        capture_output=True,
        text=True
    )

    print(resultado.stdout)

    if resultado.stderr:
        print("ERRORES:", resultado.stderr)
