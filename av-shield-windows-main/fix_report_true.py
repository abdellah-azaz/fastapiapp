path = 'web/realtime_monitor.py'
lines = open(path, 'r', encoding='utf-8').readlines()

# Corriger ligne 60 - changer report: False par report: True
lines[59] = '            json={"path": filepath, "auto": False, "report": True, "realtime": True},\n'

open(path, 'w', encoding='utf-8').writelines(lines)
print('Ligne 60 corrigee !')
print(repr(lines[59]))
