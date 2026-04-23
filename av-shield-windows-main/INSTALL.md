# 🛡️ AV-Shield Windows — Guide d'installation complet

## Ce dont vous avez besoin (à installer une seule fois)

### 1. Python 3.12
- Télécharger : https://www.python.org/downloads/
- **IMPORTANT** : Cocher "Add Python to PATH" pendant l'installation

### 2. Git
- Télécharger : https://git-scm.com/download/win
- Installer avec les options par défaut

### 3. ClamAV
- Télécharger : https://www.clamav.net/downloads
- Fichier à télécharger : **clamav-1.5.2.win.x64.msi**
- Installer avec les options par défaut

---

## Installation du projet

### Étape 1 — Cloner le projet
Ouvrir CMD et taper :
```
cd C:\
git clone https://github.com/fatima-hub03/av-shield-windows.git
cd av-shield-windows
```

### Étape 2 — Installer les bibliothèques Python
```
pip install flask flask-cors google-genai watchdog requests
```

### Étape 3 — Télécharger les signatures ClamAV
```
copy "C:\Program Files\ClamAV\conf_examples\freshclam.conf.sample" "C:\Program Files\ClamAV\freshclam.conf"
```
Ouvrir le fichier `C:\Program Files\ClamAV\freshclam.conf` avec Notepad et remplacer la ligne `Example` par `# Example`

Ensuite lancer :
```
"C:\Program Files\ClamAV\freshclam.exe"
```
*(Cette étape télécharge 110 MB de signatures — prend 2-3 minutes)*

### Étape 4 — Copier les signatures dans le projet
```
xcopy "C:\Program Files\ClamAV\database" "C:\av-shield-windows\database\" /E /I /Y
xcopy "C:\Program Files\ClamAV\certs" "C:\av-shield-windows\certs\" /E /I /Y
```

### Étape 5 — Créer le fichier de configuration

Créer le fichier `C:\av-shield-windows\web\config_local.py` avec ce contenu :
```python
GEMINI_API_KEY = "VOTRE_CLE_GEMINI"
GROQ_API_KEY = "VOTRE_CLE_GROQ"
VIRUSTOTAL_API_KEY = "VOTRE_CLE_VIRUSTOTAL"
SMTP_HOST = "sandbox.smtp.mailtrap.io"
SMTP_PORT = 2525
SMTP_USER = "VOTRE_SMTP_USER"
SMTP_PASS = "VOTRE_SMTP_PASS"
ALERT_EMAIL = "VOTRE_EMAIL"
```

---

## Lancement du projet

### Terminal 1 — Monitor temps réel
```
cd C:\av-shield-windows
python web\realtime_monitor.py
```

### Terminal 2 — Interface web
```
cd C:\av-shield-windows
python web\app.py
```

### Ouvrir le navigateur
```
http://localhost:5000
```

---

## Test rapide

Pour vérifier que tout fonctionne, ouvrir un 3ème terminal et taper :
```
python -c "open('C:\\av-shield-windows\\test_eicar.txt','w').write('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')"
```

Ensuite scanner `C:\av-shield-windows\test_eicar.txt` depuis l'interface web.
Le résultat doit être **MALWARE — Eicar-Signature**.

---

## Structure du projet
```
av-shield-windows\
├── avshield.exe          ← Binaire antivirus (déjà compilé)
├── *.dll                 ← Bibliothèques ClamAV (déjà incluses)
├── web\
│   ├── app.py            ← Interface Flask
│   ├── realtime_monitor.py ← Monitor temps réel
│   ├── ai_analyzer.py    ← Analyse IA Gemini
│   └── config_local.py   ← À créer (étape 5)
├── database\             ← Base de données SQLite
├── src\                  ← Code source C
└── INSTALL.md            ← Ce fichier
```

---

## En cas de problème

**Erreur "libclamav.dll not found"** :
```
copy "C:\Program Files\ClamAV\*.dll" C:\av-shield-windows\
```

**Erreur "Port 5000 already in use"** :
```
netstat -ano | findstr :5000
taskkill /PID [numero] /F
```

**Erreur "Module not found"** :
```
pip install flask flask-cors google-genai watchdog requests
```
