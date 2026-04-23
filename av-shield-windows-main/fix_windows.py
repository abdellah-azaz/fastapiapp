import os

# ============================================
# Fix 1 — quarantine.c : mkdir -> _mkdir + include direct.h
# ============================================
path = 'src/quarantine.c'
content = open(path, 'r', encoding='utf-8', errors='ignore').read()

# Ajouter include direct.h pour _mkdir
if '#ifdef _WIN32' not in content:
    content = content.replace(
        '#include <sys/stat.h>',
        '#include <sys/stat.h>\n#ifdef _WIN32\n#include <direct.h>\n#endif'
    )

# Remplacer mkdir(X, 0700) par _mkdir(X) sur Windows
content = content.replace(
    'mkdir(QUARANTINE_DIR, 0700)',
    '_mkdir(QUARANTINE_DIR)'
)

open(path, 'w', encoding='utf-8').write(content)
print('quarantine.c corrige !')

# ============================================
# Fix 2 — heuristic.c : ajouter memmem pour Windows
# ============================================
path = 'src/heuristic.c'
content = open(path, 'r', encoding='utf-8', errors='ignore').read()

memmem_impl = """
#ifdef _WIN32
#include <windows.h>
static void *memmem(const void *h, size_t hl, const void *n, size_t nl) {
    if (nl == 0) return (void*)h;
    if (hl < nl) return NULL;
    for (size_t i = 0; i <= hl-nl; i++) {
        if (memcmp((char*)h+i, n, nl) == 0) return (char*)h+i;
    }
    return NULL;
}
#endif
"""

# Remplacer seulement si pas encore fait
if 'memmem_impl' not in content and 'static void *memmem' not in content:
    content = content.replace('#include <string.h>', '#include <string.h>' + memmem_impl)

open(path, 'w', encoding='utf-8').write(content)
print('heuristic.c corrige !')

# ============================================
# Fix 3 — hash.h : remplacer openssl/sha.h par windows
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
