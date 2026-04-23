path = 'web/realtime_monitor.py'
lines = open(path, 'r', encoding='utf-8').readlines()

# Afficher les lignes 64-90
for i, line in enumerate(lines[63:90], start=64):
    print(f"{i}: {repr(line)}")
