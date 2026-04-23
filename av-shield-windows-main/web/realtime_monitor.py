#!/usr/bin/env python3
import platform
import threading
import time
import json
import os
import sys
from datetime import datetime

# ============================================
#   DETECTION AUTOMATIQUE WINDOWS / LINUX
# ============================================
if platform.system() == "Windows":
    WATCH_DIRS   = [
        os.path.join(os.path.expanduser("~"), "Downloads"),
        os.path.join(os.path.expanduser("~"), "Desktop"),
        os.path.join(os.path.expanduser("~"), "Documents"),
        os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp"),
        "C:\\Temp"
    ]
    BASE_PATH    = os.path.dirname(os.path.abspath(__file__))
    AVSHIELD_BIN = os.path.join(os.path.dirname(BASE_PATH), "avshield.exe")
    DB_PATH      = os.path.join(os.path.dirname(BASE_PATH), "database", "avshield.db")
    EVENTS_FILE  = os.path.join(os.path.dirname(BASE_PATH), "database", "realtime_events.json")
else:
    WATCH_DIRS   = ["/tmp", os.path.join(os.path.expanduser("~"), "Downloads"), os.path.join(os.path.expanduser("~"), "Desktop")]
    BASE_PATH    = os.path.dirname(os.path.abspath(__file__))
    AVSHIELD_BIN = os.path.join(os.path.dirname(BASE_PATH), "avshield")
    DB_PATH      = os.path.join(os.path.dirname(BASE_PATH), "database", "avshield.db")
    EVENTS_FILE  = os.path.join(os.path.dirname(BASE_PATH), "database", "realtime_events.json")

def load_events():
    if os.path.exists(EVENTS_FILE):
        with open(EVENTS_FILE, "r") as f:
            return json.load(f)
    return []

def save_event(filepath, result, threat):
    events = load_events()
    events.insert(0, {
        "filepath" : filepath,
        "filename" : os.path.basename(filepath),
        "result"   : result,
        "threat"   : threat or "None",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    events = events[:100]
    with open(EVENTS_FILE, "w") as f:
        json.dump(events, f)

def scan_file(filepath):
    try:
        if any(x in filepath for x in [".quar", "quarantine", "reports", "logs", ".tmp"]):
            return
        if not os.path.isfile(filepath):
            return
        print(f"[RT] Scan: {filepath}")
        import requests as req
        response = req.post("http://localhost:5000/api/scan",
            json={"path": filepath, "auto": False, "report": True, "realtime": True},
            timeout=60)
        file_result = "CLEAN"
        threat = "None"
        if response.status_code == 200:
            try:
                data  = response.json()
                data  = response.json()
                report = data.get("report") or {}
                files = report.get("files", [])
                # Methode 1: chercher par nom de fichier
                filename = os.path.basename(filepath).lower()
                for f_info in files:
                    fp = f_info.get("filepath", "") or f_info.get("filename", "")
                    if os.path.basename(fp).lower() == filename:
                        file_result = f_info.get("result", "CLEAN")
                        threat      = f_info.get("threat", "None")
                        break
                # Methode 2: utiliser les stats si fichier pas trouve
                if file_result == "CLEAN":
                    stats = report.get("statistics", {})
                    if stats.get("malware_files", 0) > 0:
                        file_result = "MALWARE"
                        # Recuperer le nom de la menace
                        if files:
                            threat = files[0].get("threat", "None")
                    elif stats.get("suspicious_files", 0) > 0:
                        file_result = "SUSPICIOUS"
            except Exception as e:
                print(f"[RT] Erreur parsing: {e}")
        print(f"[RT] {filepath} -> {file_result}")
        save_event(filepath, file_result, threat)
    except Exception as e:
        print(f"[RT] Erreur scan {filepath}: {e}")

def start_monitoring():
    print(f"[RT] Systeme detecte : {platform.system()}")
    print(f"[RT] Demarrage surveillance temps reel...")

    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    class Handler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory:
                time.sleep(0.5)
                threading.Thread(target=scan_file, args=(event.src_path,), daemon=True).start()
        def on_moved(self, event):
            if not event.is_directory:
                time.sleep(0.5)
                threading.Thread(target=scan_file, args=(event.dest_path,), daemon=True).start()

    observer = Observer()
    for d in WATCH_DIRS:
        if not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        observer.schedule(Handler(), d, recursive=False)
        print(f"[RT] Surveillance: {d}")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_monitoring()
