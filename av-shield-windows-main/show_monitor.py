path = 'web/realtime_monitor.py'
lines = open(path, 'r', encoding='utf-8').readlines()

# Afficher les lignes 60-90
for i, line in enumerate(lines[59:90], start=60):
    print(f"{i}: {repr(line)}")
