import requests 
r = requests.post('http://localhost:5000/api/scan', json={'path': 'C:\\av-shield\\eicar.txt', 'report': True, 'realtime': True}) 
data = r.json() 
print('report:', data.get('report')) 
print('files:', (data.get('report') or {}).get('files')) 
