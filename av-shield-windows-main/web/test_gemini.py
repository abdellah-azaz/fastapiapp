import sys 
sys.path.insert(0,'.') 
from ai_analyzer import analyze_threat 
result = analyze_threat('virus.txt','MALWARE','Eicar-Signature',0,0) 
print(result) 
