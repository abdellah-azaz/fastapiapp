content = open('src/heuristic.c', 'r', encoding='utf-8', errors='ignore').read()

memmem_impl = '''
#ifdef _WIN32
static void *memmem(const void *h, size_t hl, const void *n, size_t nl) {
    if (nl == 0) return (void*)h;
    if (hl < nl) return NULL;
    for (size_t i = 0; i <= hl-nl; i++) {
        if (memcmp((char*)h+i, n, nl) == 0) return (char*)h+i;
    }
    return NULL;
}
#endif
'''

content = content.replace('#include <string.h>', '#include <string.h>' + memmem_impl)
open('src/heuristic.c', 'w', encoding='utf-8').write(content)
print('heuristic.c corrige !')
