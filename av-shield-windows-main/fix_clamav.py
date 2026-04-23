path = 'src/clamav_engine.c'
content = open(path, 'r', encoding='utf-8', errors='ignore').read()

# Remplacer cl_retdbdir() par le chemin Windows
old = 'rc = cl_load(cl_retdbdir(), engine->engine,'
new = '''#ifdef _WIN32
    const char *db_path = "C:\\\\Program Files\\\\ClamAV\\\\database";
#else
    const char *db_path = cl_retdbdir();
#endif
    rc = cl_load(db_path, engine->engine,'''

content = content.replace(old, new)

open(path, 'w', encoding='utf-8').write(content)
print('clamav_engine.c corrige !')
