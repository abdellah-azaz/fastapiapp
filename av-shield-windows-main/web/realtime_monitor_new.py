#!/usr/bin/env python3
import platform
import threading
import time
import json
import os
import re
from datetime import datetime

# ============================================
#   DETECTION AUTOMATIQUE WINDOWS / LINUX
# ============================================
if platform.system() == "Windows":
    WATCH_DIRS = [
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
    REPORTS_DIR  = os.path.join(os.path.dirname(BASE_PATH), "reports")
else:
    WATCH_DIRS = [
        "/tmp",
        os.path.join(os.path.expanduser("~"), "Downloads"),
        os.path.join(os.path.expanduser("~"), "Desktop")
    ]
    BASE_PATH    = os.path.dirname(os.path.abspath(__file__))
    AVSHIELD_BIN = os.path.join(os.path.dirname(BASE_PATH), "avshield")
    DB_PATH      = os.path.join(os.path.dirname(BASE_PATH), "database", "avshield.db")
    EVENTS_FILE  = os.path.join(os.path.dirname(BASE_PATH), "database", "realtime_events.json")
    REPORTS_DIR  = os.path.join(os.path.dirname(BASE_PATH), "reports")

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
    events = events[:50]
    with open(EVENTS_FILE, "w") as f:
        json.dump(events, f)

def read_last_report():
    """Lire le dernier rapport JSON generé"""
    try:
        if not os.path.exists(REPORTS_DIR):
            return None
        reports = [
            os.path.join(REPORTS_DIR, f)
            for f in os.listdir(REPORTS_DIR)
            if f.startswith("RPT_") and f.endswith(".json")
        ]
        if not reports:
            return None
        latest = max(reports, key=os.path.getmtime)
        # Verifier que le rapport est recent (moins de 30 secondes)
        if time.time() - os.path.getmtime(latest) > 30:
            return None
        with open(latest, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        # Corriger les backslashes Windows invalides dans le JSON
        raw = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', raw)
        return json.loads(raw)
    except Exception as e:
        print(f"[RT] Erreur lecture rapport: {e}")
        return None

def scan_file(filepath):
    try:
        if any(x in filepath for x in [".quar", "quarantine", "reports", "logs", ".tmp"]):
            return
        if not os.path.isfile(filepath):
            return

        print(f"[RT] Scan: {filepath}")

        import requests as req
        scan_time = time.time()
        response = req.post("http://localhost:5000/api/scan",
            json={"path": filepath, "auto": False, "report": True, "realtime": True},
            timeout=60)

        file_result = "CLEAN"
        threat = "None"

        if response.status_code == 200:
            try:
                data = response.json()

                # Methode 1 : lire depuis la reponse API
                report = data.get("report")
                if report and report.get("files"):
                    for f_info in report["files"]:
                        fp = f_info.get("filepath", "")
                        # Comparer juste le nom du fichier
                        if os.path.basename(fp).lower() == os.path.basename(filepath).lower():
                            file_result = f_info.get("result", "CLEAN")
                            threat = f_info.get("threat", "None")
                            break

                # Methode 2 : lire directement le dernier rapport JSON
                if file_result == "CLEAN":
                    time.sleep(0.5)
                    report_data = read_last_report()
                    if report_data and report_data.get("files"):
                        for f_info in report_data["files"]:
                            fp = f_info.get("filepath", "")
                            if os.path.basename(fp).lower() == os.path.basename(filepath).lower():
                                file_result = f_info.get("result", "CLEAN")
                                threat = f_info.get("threat", "None")
                                break

                # Methode 3 : utiliser les statistiques
                if file_result == "CLEAN":
                    report = data.get("report") or {}
                    stats = report.get("statistics", {})
                    if stats.get("malware_files", 0) > 0:
                        file_result = "MALWARE"
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
            try:
                os.makedirs(d, exist_ok=True)
            except:
                pass
        if os.path.exists(d):
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
