import re

# Fix 1 — index.html : corriger les données du graphe
path = 'web/templates/index.html'
content = open(path, 'r', encoding='utf-8').read()

old = "data: [{{ stats.total_clean }}, {{ stats.total_threats }}, {{ stats.total_quarantine }}],"
new = "data: [{{ stats.total_clean }}, {{ stats.total_suspicious }}, {{ stats.total_malware }}],"

if old in content:
    content = content.replace(old, new)
    print('index.html graphe corrige !')
else:
    print('Pattern index.html non trouve!')
    idx = content.find('data: [')
    print(repr(content[idx:idx+100]))

# Fix aussi les labels du graphe
old2 = "<span style=\"color:#ffa502;font-weight:bold;margin-left:auto;\">{{ stats.total_threats }}</span>"
new2 = "<span style=\"color:#ffa502;font-weight:bold;margin-left:auto;\">{{ stats.total_suspicious }}</span>"
content = content.replace(old2, new2)

old3 = "<span style=\"color:#ff4757;font-weight:bold;margin-left:auto;\">{{ stats.total_quarantine }}</span>"
new3 = "<span style=\"color:#ff4757;font-weight:bold;margin-left:auto;\">{{ stats.total_malware }}</span>"
content = content.replace(old3, new3)

open(path, 'w', encoding='utf-8').write(content)
print('index.html corrige !')

# Fix 2 — app.py : ajouter total_suspicious et total_malware aux stats
path2 = 'web/app.py'
content2 = open(path2, 'r', encoding='utf-8').read()

old4 = "'total_clean'     : db.execute(\"SELECT SUM(clean_files) FROM scans\").fetchone()[0] or 0"
new4 = "'total_clean'     : db.execute(\"SELECT SUM(clean_files) FROM scans\").fetchone()[0] or 0,\n            'total_suspicious': db.execute(\"SELECT SUM(suspicious_files) FROM scans\").fetchone()[0] or 0,\n            'total_malware'   : db.execute(\"SELECT SUM(malware_files) FROM scans\").fetchone()[0] or 0"

if old4 in content2:
    content2 = content2.replace(old4, new4)
    print('app.py stats corrige !')
else:
    print('Pattern app.py non trouve!')
    idx = content2.find('total_clean')
    print(repr(content2[idx:idx+200]))

open(path2, 'w', encoding='utf-8').write(content2)
print('Termine !')
