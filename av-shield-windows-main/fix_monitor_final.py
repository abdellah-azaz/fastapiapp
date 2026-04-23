path = 'web/realtime_monitor.py'
lines = open(path, 'r', encoding='utf-8').readlines()

# Remplacer les lignes 67-83 par une logique correcte
new_lines = [
    '                data  = response.json()\n',
    '                report = data.get("report") or {}\n',
    '                files = report.get("files", [])\n',
    '                # Methode 1: chercher par nom de fichier\n',
    '                filename = os.path.basename(filepath).lower()\n',
    '                for f_info in files:\n',
    '                    fp = f_info.get("filepath", "") or f_info.get("filename", "")\n',
    '                    if os.path.basename(fp).lower() == filename:\n',
    '                        file_result = f_info.get("result", "CLEAN")\n',
    '                        threat      = f_info.get("threat", "None")\n',
    '                        break\n',
    '                # Methode 2: utiliser les stats si fichier pas trouve\n',
    '                if file_result == "CLEAN":\n',
    '                    stats = report.get("statistics", {})\n',
    '                    if stats.get("malware_files", 0) > 0:\n',
    '                        file_result = "MALWARE"\n',
    '                        # Recuperer le nom de la menace\n',
    '                        if files:\n',
    '                            threat = files[0].get("threat", "None")\n',
    '                    elif stats.get("suspicious_files", 0) > 0:\n',
    '                        file_result = "SUSPICIOUS"\n',
]

# Remplacer lignes 67-83 (index 66-82)
lines[66:83] = new_lines

open(path, 'w', encoding='utf-8').writelines(lines)
print('Monitor corrige !')

# Verifier
for i, line in enumerate(lines[63:90], start=64):
    print(f"{i}: {repr(line)}")
