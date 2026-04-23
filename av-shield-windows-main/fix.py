content = open('src/quarantine.c', 'r', encoding='utf-8', errors='ignore').read() 
content = content.replace('mkdir(QUARANTINE_DIR, 0700)', '_mkdir(QUARANTINE_DIR)') 
open('src/quarantine.c', 'w', encoding='utf-8').write(content) 
print('quarantine.c corrige !') 
