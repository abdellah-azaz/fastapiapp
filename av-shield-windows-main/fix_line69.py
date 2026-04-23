path = 'web/realtime_monitor.py'
lines = open(path, 'r', encoding='utf-8').readlines()

# Afficher les lignes autour de l'erreur
for i, line in enumerate(lines[65:75], start=66):
    print(f"{i}: {repr(line)}")

# Corriger la ligne 69 (index 68)
lines[68] = '                filepath_norm = filepath.replace("\\\\", "/").replace("\\\\", "/").lower()\n'

open(path, 'w', encoding='utf-8').writelines(lines)
print('\nLigne 69 corrigee !')
print(repr(lines[68]))
