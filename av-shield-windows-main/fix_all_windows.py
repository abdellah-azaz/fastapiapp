import os

# ============================================
# Fix 1 — quarantine.c
# ============================================
path = 'src/quarantine.c'
content = open(path, 'r', encoding='utf-8', errors='ignore').read()

windows_fix = """
#ifdef _WIN32
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#endif
"""

if '#define mkdir' not in content:
    content = content.replace(
        '#include <sys/stat.h>',
        '#include <sys/stat.h>' + windows_fix
    )

open(path, 'w', encoding='utf-8').write(content)
print('quarantine.c corrige !')

# ============================================
# Fix 2 — heuristic.c
# ============================================
path = 'src/heuristic.c'
content = open(path, 'r', encoding='utf-8', errors='ignore').read()

memmem_fix = """
#ifdef _WIN32
static void *memmem(const void *h, size_t hl, const void *n, size_t nl) {
    if (nl == 0) return (void*)h;
    if (hl < nl) return NULL;
    for (size_t i = 0; i <= hl - nl; i++) {
        if (memcmp((char*)h + i, n, nl) == 0) return (char*)h + i;
    }
    return NULL;
}
#endif
"""

if 'static void *memmem' not in content:
    # Ajouter après le dernier #include
    lines = content.split('\n')
    last_include = 0
    for i, line in enumerate(lines):
        if line.startswith('#include'):
            last_include = i
    lines.insert(last_include + 1, memmem_fix)
    content = '\n'.join(lines)

open(path, 'w', encoding='utf-8').write(content)
print('heuristic.c corrige !')

# ============================================
# Fix 3 — scanner.c : S_ISLNK et lstat
# ============================================
path = 'src/scanner.c'
content = open(path, 'r', encoding='utf-8', errors='ignore').read()

scanner_fix = """
#ifdef _WIN32
#include <windows.h>
#define S_ISLNK(m) 0
#define lstat stat
#endif
"""

if '#define S_ISLNK' not in content:
    lines = content.split('\n')
    last_include = 0
    for i, line in enumerate(lines):
        if line.startswith('#include'):
            last_include = i
    lines.insert(last_include + 1, scanner_fix)
    content = '\n'.join(lines)

open(path, 'w', encoding='utf-8').write(content)
print('scanner.c corrige !')

# ============================================
# Fix 4 — hash.h
# ============================================
path = 'include/hash.h'
content = open(path, 'r', encoding='utf-8', errors='ignore').read()

if '#ifdef _WIN32' not in content:
    content = content.replace(
        '#include <openssl/sha.h>',
        '#ifdef _WIN32\n#include "C:/Program Files/OpenSSL-Win64/include/openssl/sha.h"\n#else\n#include <openssl/sha.h>\n#endif'
    )

open(path, 'w', encoding='utf-8').write(content)
print('hash.h corrige !')

print('\nTous les fichiers sont corriges !')
