path = 'web/app.py'
lines = open(path, 'r', encoding='utf-8').readlines()

# Chercher la ligne qui fait json.load
for i, line in enumerate(lines):
    if 'json.load' in line and 'report' in line.lower():
        print(f"Ligne {i+1}: {repr(line)}")

# Remplacer le bloc de lecture JSON
old = """            try:
                with open(json_path, "r") as f:
                    report_data = json.load(f)
            except:
                pass"""

new = """            try:
                with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw = f.read()
                # Corriger les backslashes Windows dans le JSON
                import re as _re
                raw = _re.sub(r'(?<!\\\\)\\\\(?!["\\\\/bfnrt]|u[0-9a-fA-F]{4})', r'\\\\\\\\', raw)
                report_data = json.loads(raw)
            except Exception as _je:
                print(f"[JSON ERROR] {_je}")
                report_data = None"""

content = open(path, 'r', encoding='utf-8').read()
if old in content:
    content = content.replace(old, new)
    print("json.load corrige !")
else:
    print("Pattern non trouve, cherche...")
    idx = content.find('json.load')
    print(repr(content[idx-200:idx+200]))

open(path, 'w', encoding='utf-8').write(content)
