path = 'web/app.py'
content = open(path, 'r', encoding='utf-8').read()

# Chercher et remplacer tout le bloc subprocess
old = """        import time as _time
        scan_start_time = _time.time()
        result = subprocess.run(
            cmd, capture_output=True,
            timeout=300,
            cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN))
        )
        result_stdout = result.stdout.decode('utf-8', errors='ignore') if result.stdout else ''
        result_stderr = result.stderr.decode('utf-8', errors='ignore') if result.stderr else ''"""

new = """        import time as _time
        scan_start_time = _time.time()
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN))
        )
        result_stdout = proc.stdout.decode('utf-8', errors='ignore') if proc.stdout else ''
        result_stderr = proc.stderr.decode('utf-8', errors='ignore') if proc.stderr else ''"""

if old in content:
    content = content.replace(old, new)
    print("Bloc subprocess remplace !")
else:
    # Essayer une autre approche - chercher juste le subprocess.run
    print("Pattern non trouve, recherche alternative...")
    # Afficher le contexte autour de subprocess.run
    idx = content.find('subprocess.run')
    if idx != -1:
        print(f"Trouve a position {idx}:")
        print(repr(content[idx-100:idx+300]))

open(path, 'w', encoding='utf-8').write(content)
print('Termine!')
