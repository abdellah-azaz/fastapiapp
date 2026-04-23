path = 'web/realtime_monitor.py'
content = open(path, 'r', encoding='utf-8').read()

old = '''        if response.status_code == 200:
            try:
                data  = response.json()
                files = (data.get("report") or {}).get("files", [])
                for f_info in files:
                    if f_info.get("filepath") == filepath:
                        file_result = f_info.get("result", "CLEAN")
                        threat      = f_info.get("threat", "None")
                        break
            except Exception as e:
                print(f"[RT] Erreur parsing: {e}")'''

new = '''        if response.status_code == 200:
            try:
                data  = response.json()
                files = (data.get("report") or {}).get("files", [])
                # Normaliser les chemins pour comparaison
                filepath_norm = filepath.replace("\\\\", "/").replace("\\", "/").lower()
                for f_info in files:
                    fp = f_info.get("filepath", "")
                    fp_norm = fp.replace("\\\\", "/").replace("\\", "/").lower()
                    if fp_norm == filepath_norm or os.path.basename(fp) == os.path.basename(filepath):
                        file_result = f_info.get("result", "CLEAN")
                        threat      = f_info.get("threat", "None")
                        break
                # Si pas trouve dans files, chercher dans les stats
                if file_result == "CLEAN" and not files:
                    stats = (data.get("report") or {}).get("statistics", {})
                    if stats.get("malware_files", 0) > 0:
                        file_result = "MALWARE"
                    elif stats.get("suspicious_files", 0) > 0:
                        file_result = "SUSPICIOUS"
            except Exception as e:
                print(f"[RT] Erreur parsing: {e}")'''

if old in content:
    content = content.replace(old, new)
    print('realtime_monitor.py corrige !')
else:
    print('Pattern non trouve!')
    idx = content.find('response.status_code == 200')
    print(repr(content[idx:idx+500]))

open(path, 'w', encoding='utf-8').write(content)
