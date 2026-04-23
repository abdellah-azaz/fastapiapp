path = 'web/templates/scan.html'
content = open(path, 'r', encoding='utf-8').read()

# Corriger les regex pour accepter \r\n et \n
old1 = r'text.match(/🏷️ CLASSIFICATION\s*\n([\s\S]*?)(?=🎯|$)/)'
new1 = r'text.match(/🏷️ CLASSIFICATION[\s\S]*?[\r\n]+([\s\S]*?)(?=🎯|$)/)'

old2 = r'text.match(/🎯 TYPE DE MENACE[\s\S]*?\n([\s\S]*?)(?=⚠️|$)/)'
new2 = r'text.match(/🎯 TYPE DE MENACE[\s\S]*?[\r\n]+([\s\S]*?)(?=⚠️|$)/)'

old3 = r'text.match(/⚠️ POURQUOI[\s\S]*?\n([\s\S]*?)(?=🛡️|$)/)'
new3 = r'text.match(/⚠️ POURQUOI[\s\S]*?[\r\n]+([\s\S]*?)(?=🛡️|$)/)'

if old1 in content:
    content = content.replace(old1, new1)
    print('CLASSIFICATION regex corrige !')
else:
    print('Pattern 1 non trouve!')

if old2 in content:
    content = content.replace(old2, new2)
    print('TYPE DE MENACE regex corrige !')
else:
    print('Pattern 2 non trouve!')

if old3 in content:
    content = content.replace(old3, new3)
    print('POURQUOI regex corrige !')
else:
    print('Pattern 3 non trouve!')

open(path, 'w', encoding='utf-8').write(content)
print('Termine !')
