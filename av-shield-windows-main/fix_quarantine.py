path = 'src/quarantine.c'
content = open(path, 'r', encoding='utf-8', errors='ignore').read()

# Ajouter direct.h au debut du fichier
fix = '#ifdef _WIN32\n#include <direct.h>\n#endif\n'

if '#include <direct.h>' not in content:
    content = fix + content

open(path, 'w', encoding='utf-8').write(content)
print('quarantine.c corrige !')
print('Debut du fichier:')
print(content[:200])
