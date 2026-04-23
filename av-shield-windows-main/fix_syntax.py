path = 'web/app.py'
content = open(path, 'r', encoding='utf-8').read()

old = """proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN)))
        result_stdout = proc.stdout.decode('utf-8', errors='ignore') if proc.stdout else ''
        result_stderr = proc.stderr.decode('utf-8', errors='ignore') if proc.stderr else ''"""

new = """proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN)))
        result_stdout = proc.stdout.decode('utf-8', errors='ignore') if proc.stdout else ''
        result_stderr = proc.stderr.decode('utf-8', errors='ignore') if proc.stderr else ''
        """

if old in content:
    content = content.replace(old, new)
    print('Syntaxe corrigee !')
else:
    # Afficher les lignes 80-90
    lines = content.split('\n')
    for i, line in enumerate(lines[78:92], start=79):
        print(f"{i}: {repr(line)}")

open(path, 'w', encoding='utf-8').write(content)
