# 🛡️ AV-Shield — Antivirus Multi-Couches avec IA

Antivirus développé en C avec interface web Flask, combinant 4 couches de détection, analyse IA et threat intelligence mondiale.

## 🏗️ Architecture
```
av-shield/
├── src/                        # Code source C
│   ├── main.c                  # Point d'entrée principal
│   ├── scanner.c               # Orchestrateur scan multi-couches
│   ├── clamav_engine.c         # Couche 1 : ClamAV
│   ├── hash.c                  # Couche 2 : SHA256
│   ├── heuristic.c             # Couche 3 : Heuristique (43 IoC)
│   ├── entropy.c               # Couche 4 : Entropie Shannon
│   ├── quarantine.c            # Gestion quarantaine
│   ├── report.c                # Rapports JSON/HTML
│   └── database.c              # SQLite
├── web/
│   ├── app.py                  # Serveur Flask API REST
│   ├── ai_analyzer.py          # Module IA (Groq/Llama3)
│   ├── threat_intelligence.py  # Module VirusTotal
│   ├── realtime_monitor.py     # Surveillance temps réel
│   └── templates/              # Pages HTML
├── database/avshield.db        # Base SQLite
├── quarantine/                 # Fichiers isolés (.quar)
├── reports/                    # Rapports JSON/HTML
└── avshield                    # Binaire compilé
```

## 🔍 Les 4 Couches de Détection

| Couche | Technologie | Détecte |
|--------|-------------|---------|
| 1 | ClamAV | Malwares connus (3.6M signatures) |
| 2 | SHA256 | Hash malveillants connus |
| 3 | Heuristique (43 IoC) | Menaces inconnues / zero-day |
| 4 | Entropie Shannon | Ransomwares / fichiers obfusqués |

## 🤖 Fonctionnalités IA

- **Analyse IA** — Llama3 via Groq : classification, type de menace, recommandations
- **Threat Intelligence** — VirusTotal API : 70+ moteurs antivirus mondiaux
- **Probabilité de menace** — score calculé automatiquement
- **Rapport HTML** — téléchargeable avec toute l'analyse

## 🛡️ Protection Temps Réel

Surveillance automatique des dossiers `/tmp`, `/Downloads`, `/Desktop` avec inotifywait. Détection immédiate et alerte sur le dashboard.

## ⚙️ Installation

### 1. Prérequis
```bash
sudo apt-get install gcc make libclamav-dev libssl-dev libsqlite3-dev inotify-tools
pip install flask groq requests --break-system-packages
```

### 2. Cloner et compiler
```bash
git clone https://github.com/fatima-hub03/av-shield.git
cd av-shield
make
```

### 3. Configurer les clés API
```bash
cat > web/config_local.py << 'CONF'
GROQ_API_KEY = "VOTRE_CLE_GROQ"
VIRUSTOTAL_API_KEY = "VOTRE_CLE_VIRUSTOTAL"
CONF
```
- Clé Groq gratuite : https://console.groq.com
- Clé VirusTotal gratuite : https://www.virustotal.com

### 4. Lancer le projet
```bash
python3 web/realtime_monitor.py > /tmp/monitor.log 2>&1 &
sleep 2
python3 web/app.py
```

### 5. Ouvrir dans le navigateur
```
http://localhost:5000
```

## 🧪 Fichiers de test
```bash
# CLEAN
echo "print('Hello')" > /tmp/test_clean.py

# SUSPICIOUS
cat > /tmp/test_suspect.py << 'TEST'
import os, socket
os.popen("cat /etc/passwd")
socket.socket().connect(("10.0.0.1", 4444))
TEST

# MALWARE (fichier de test standard EICAR)
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/test_malware.com
```

## 🌐 API REST

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | /api/scan | Lancer un scan |
| GET | /api/stats | Statistiques globales |
| POST | /api/ai-analyze | Analyse IA d'un fichier |
| POST | /api/threat-intel | Threat Intelligence VirusTotal |
| GET | /api/realtime-events | Événements temps réel |
| GET | /api/quarantine | Liste quarantaine |
| POST | /api/quarantine/restore | Restaurer un fichier |

## 🖥️ Pages disponibles

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | / | Stats, protection temps réel, graphique |
| Scanner | /scan | Scan manuel + analyse IA |
| Quarantaine | /quarantine | Fichiers isolés |
| Rapports | /reports-page | Rapports JSON/HTML |

## 📊 Format Rapport JSON
```json
{
  "av_shield": "AV-Shield v1.0.0",
  "report_id": "SCAN_20260315_091553",
  "scan_target": "/chemin/fichier",
  "statistics": {
    "total_files": 1,
    "clean_files": 0,
    "suspicious_files": 0,
    "malware_files": 1
  },
  "files": [{
    "filename": "test.com",
    "result": "MALWARE",
    "threat": "Eicar-Signature",
    "heuristic_score": 0,
    "entropy": 0.0,
    "sha256": "275a021bbfb648...",
    "quarantined": true
  }]
}
```

## 🛠️ Technologies

| Composant | Technologie |
|-----------|-------------|
| Moteur antivirus | C (GCC) |
| Détection signatures | libclamav |
| Hachage | SHA-256 |
| Base de données | SQLite3 |
| Interface web | Python Flask |
| Analyse IA | Groq / Llama3 |
| Threat Intelligence | VirusTotal API |
| Surveillance | inotifywait |
| Frontend | HTML5, CSS3, JavaScript |

## 👤 Auteur

Fatima — [@fatima-hub03](https://github.com/fatima-hub03)
