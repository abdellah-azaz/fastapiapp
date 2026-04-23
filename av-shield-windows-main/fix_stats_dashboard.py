path = 'web/app.py'
lines = open(path, 'r', encoding='utf-8').readlines()

# Afficher les lignes autour de 41
for i, line in enumerate(lines[37:50], start=38):
    print(f"{i}: {repr(line)}")

# Corriger la ligne 41 (index 40)
lines[40] = '            "total_clean"     : db.execute("SELECT SUM(clean_files) FROM scans").fetchone()[0] or 0,\n'
# Ajouter les nouvelles lignes après
lines.insert(41, '            "total_suspicious": db.execute("SELECT SUM(suspicious_files) FROM scans").fetchone()[0] or 0,\n')
lines.insert(42, '            "total_malware"   : db.execute("SELECT SUM(malware_files) FROM scans").fetchone()[0] or 0\n')

open(path, 'w', encoding='utf-8').writelines(lines)
print('\napp.py corrige !')

# Verifier
for i, line in enumerate(lines[37:50], start=38):
    print(f"{i}: {repr(line)}")
