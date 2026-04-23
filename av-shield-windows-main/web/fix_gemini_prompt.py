path = 'ai_analyzer.py'
content = open(path, 'r', encoding='utf-8').read()

old = """Donne une analyse structurée avec exactement ces 5 sections :

🏷️ CLASSIFICATION"""

new = """Donne une analyse structurée avec exactement ces 5 sections. IMPORTANT: N'utilise pas ** pour le gras, écris le texte normalement sans formatage markdown :

🏷️ CLASSIFICATION"""

if old in content:
    content = content.replace(old, new)
    print('ai_analyzer.py corrige !')
else:
    print('Pattern non trouve!')
    idx = content.find('5 sections')
    print(repr(content[idx:idx+200]))

open(path, 'w', encoding='utf-8').write(content)
