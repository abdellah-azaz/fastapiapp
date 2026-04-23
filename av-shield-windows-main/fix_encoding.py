path = 'web/app.py'
content = open(path, 'r', encoding='utf-8').read()

# Corriger subprocess.run pour utiliser encoding utf-8
old = """result = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=300,
            cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN))
        )"""

new = """result = subprocess.run(
            cmd, capture_output=True,
            timeout=300,
            cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN))
        )
        result_stdout = result.stdout.decode('utf-8', errors='ignore') if result.stdout else ''
        result_stderr = result.stderr.decode('utf-8', errors='ignore') if result.stderr else ''"""

content = content.replace(old, new)

# Corriger les references a result.stdout et result.stderr
content = content.replace('"output": result.stdout,', '"output": result_stdout,')
content = content.replace('"errors": result.stderr,', '"errors": result_stderr,')

open(path, 'w', encoding='utf-8').write(content)
print('app.py corrige !')
