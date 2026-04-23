path = 'web/app.py'
lines = open(path, 'r', encoding='utf-8').readlines()

# Corriger la ligne 84 (index 83)
lines[83] = "        result_stderr = proc.stderr.decode('utf-8', errors='ignore') if proc.stderr else ''\n"

open(path, 'w', encoding='utf-8').writelines(lines)
print('Ligne 84 corrigee !')
print('Verification:')
print(repr(lines[83]))
