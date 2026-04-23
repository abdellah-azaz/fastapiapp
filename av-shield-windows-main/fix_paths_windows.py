import os

path = 'web/app.py'
content = open(path, 'r', encoding='utf-8').read()

# Fix 1 — Scan rapide : changer /home/fatima/Downloads par Downloads Windows
import platform
if platform.system() == 'Windows':
    downloads = os.path.join(os.path.expanduser("~"), "Downloads")
else:
    downloads = "/home/fatima/Downloads"

content = content.replace(
    '/home/fatima/Downloads',
    downloads.replace('\\', '\\\\')
)

# Fix 2 — Dossiers surveillés dans le dashboard
content = content.replace(
    '/tmp  |  /Downloads  |  /Desktop',
    'Downloads | Desktop | Documents'
)

open(path, 'w', encoding='utf-8').write(content)
print('app.py corrige !')
print(f'Downloads path: {downloads}')
