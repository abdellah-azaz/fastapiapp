path = 'web/realtime_monitor.py'
lines = open(path, 'r', encoding='utf-8').readlines()

# Corriger lignes 69 et 72 (index 68 et 71)
lines[68] = '                filepath_norm = filepath.replace("\\\\", "/").lower()\n'
lines[71] = '                    fp_norm = fp.replace("\\\\", "/").lower()\n'

open(path, 'w', encoding='utf-8').writelines(lines)
print('Lignes 69 et 72 corrigees !')
print(repr(lines[68]))
print(repr(lines[71]))
