path = 'web/app.py'
content = open(path, 'r', encoding='utf-8').read()

old = 'result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN)))'

new = '''proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN)))
        result_stdout = proc.stdout.decode('utf-8', errors='ignore') if proc.stdout else ''
        result_stderr = proc.stderr.decode('utf-8', errors='ignore') if proc.stderr else '''''

if old in content:
    content = content.replace(old, new)
    # Corriger les references
    content = content.replace('"output": result.stdout,', '"output": result_stdout,')
    content = content.replace('"errors": result.stderr,', '"errors": result_stderr,')
    print('subprocess corrige !')
else:
    print('Pattern non trouve!')
    print(repr(content[3050:3250]))

open(path, 'w', encoding='utf-8').write(content)
