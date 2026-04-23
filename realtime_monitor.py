#!/usr/bin/env python3
"""
Moniteur temps réel Crypton — Détection automatique Linux / Windows.
Surveille les dossiers sensibles et déclenche un scan AV-Shield
à chaque nouveau fichier détecté.
"""
import platform
import subprocess
import threading
import time
import json
import os
import requests as req
from datetime import datetime

# ============================================
#   CONFIGURATION SELON L'OS
# ============================================
SYSTEM = platform.system()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_HOME = os.path.expanduser("~")

if SYSTEM == "Windows":
    WATCH_DIRS = [
        os.path.join(USER_HOME, "Downloads"),
        os.path.join(USER_HOME, "Desktop"),
        os.path.join(USER_HOME, "Documents"),
        os.path.join(USER_HOME, "AppData", "Local", "Temp"),
        "C:\\Temp",
    ]
else:
    WATCH_DIRS = [
        "/tmp",
        os.path.join(USER_HOME, "Downloads"),
        os.path.join(USER_HOME, "Desktop"),
    ]

# API FastAPI (Crypton)
API_URL = "http://localhost:8000/scannerav"
EVENTS_FILE = os.path.join(BASE_DIR, "database", "realtime_events.json")

IGNORE_PATTERNS = [
    ".quar", "/quarantine/", "\\quarantine\\",
    "/reports/", "\\reports\\",
    "/logs/", "\\logs\\",
    ".tmp", ".git", "realtime_events.json",
]


# ============================================
#   EVENTS PERSISTENCE
# ============================================
def load_events():
    if os.path.exists(EVENTS_FILE):
        try:
            with open(EVENTS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_event(filepath, result, threat):
    events = load_events()
    events.insert(0, {
        "filepath": filepath,
        "filename": os.path.basename(filepath),
        "result": result,
        "threat": threat or "None",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    events = events[:50]  # Garder les 50 derniers événements
    os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
    with open(EVENTS_FILE, "w") as f:
        json.dump(events, f, indent=2)


# ============================================
#   SCANNER
# ============================================
def scan_file(filepath):
    try:
        # Ignorer les fichiers système, temporaires ou internes au projet
        if any(x in filepath for x in IGNORE_PATTERNS):
            return
        if not os.path.isfile(filepath):
            return

        print(f"[RT-MONITOR] Nouveau fichier détecté : {filepath}")

        # Appel à l'API FastAPI
        try:
            payload = {"path": filepath, "auto": True, "report": True}
            response = req.post(API_URL, json=payload, timeout=120)
        except Exception as e:
            print(f"[RT-MONITOR] Erreur connexion API FastAPI: {e}")
            return

        file_result = "CLEAN"
        threat = "None"

        if response.status_code == 200:
            data = response.json()
            if data.get("success") and data.get("report"):
                report = data["report"]
                if report.get("files") and len(report["files"]) > 0:
                    f_info = report["files"][0]
                    file_result = f_info.get("result", "CLEAN")
                    threat = f_info.get("threat", "None")

        save_event(filepath, file_result, threat)
        print(f"[RT-MONITOR] Résultat du scan : {filepath} → {file_result} ({threat})")

    except Exception as e:
        print(f"[RT-MONITOR] Erreur lors du scan de {filepath}: {e}")


# ============================================
#   WATCHERS — LINUX
# ============================================
def watch_directory_inotify(directory):
    """Surveillance via inotifywait (Linux uniquement, le plus efficace)."""
    print(f"[RT-MONITOR] Surveillance active (inotify) : {directory}")
    try:
        process = subprocess.Popen(
            ["inotifywait", "-m", "-e", "create,moved_to", "--format", "%w%f", directory],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        for line in process.stdout:
            filepath = line.strip()
            if filepath:
                time.sleep(0.5)
                threading.Thread(target=scan_file, args=(filepath,), daemon=True).start()
    except Exception as e:
        print(f"[RT-MONITOR] Erreur inotify sur {directory}: {e}")


def watch_directory_polling(directory):
    """Surveillance via polling (fallback universel)."""
    print(f"[RT-MONITOR] Surveillance active (polling) : {directory}")
    known_files = {}

    if os.path.exists(directory):
        for f in os.listdir(directory):
            try:
                path = os.path.join(directory, f)
                if os.path.isfile(path):
                    known_files[f] = os.path.getmtime(path)
            except Exception:
                pass

    while True:
        try:
            if os.path.exists(directory):
                current_files = os.listdir(directory)
                for f in current_files:
                    filepath = os.path.join(directory, f)
                    try:
                        if os.path.isfile(filepath):
                            mtime = os.path.getmtime(filepath)
                            if f not in known_files or mtime > known_files[f]:
                                print(f"[RT-MONITOR] Activité détectée via polling : {f}")
                                threading.Thread(target=scan_file, args=(filepath,), daemon=True).start()
                                known_files[f] = mtime
                    except Exception:
                        continue

                # Nettoyage des fichiers supprimés
                current_set = set(current_files)
                for f in list(known_files.keys()):
                    if f not in current_set:
                        del known_files[f]
        except Exception as e:
            print(f"[RT-MONITOR] Erreur polling sur {directory}: {e}")
        time.sleep(5)


# ============================================
#   WATCHERS — WINDOWS (watchdog)
# ============================================
def watch_directories_watchdog(directories):
    """Surveillance via watchdog (Windows & cross-platform)."""
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        print("[RT-MONITOR] watchdog non installé — passage en mode polling.")
        # Fallback au polling sur Windows si watchdog n'est pas disponible
        for d in directories:
            t = threading.Thread(target=watch_directory_polling, args=(d,), daemon=True)
            t.start()
        return

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
    for d in directories:
        if not os.path.exists(d):
            try:
                os.makedirs(d, exist_ok=True)
            except Exception:
                print(f"[RT-MONITOR] Impossible de créer/surveiller {d}")
                continue
        observer.schedule(Handler(), d, recursive=False)
        print(f"[RT-MONITOR] Surveillance active (watchdog) : {d}")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


# ============================================
#   POINT D'ENTRÉE
# ============================================
def start_monitoring():
    print(f"🛡️  Démarrage du Moniteur Temps Réel Crypton — OS détecté : {SYSTEM}")
    print("[RT-MONITOR] Attente du démarrage de l'API (5s)...")
    time.sleep(5)
    print("=" * 45)

    # Filtrer les dossiers existants (ou créables)
    valid_dirs = []
    for d in WATCH_DIRS:
        if not os.path.exists(d):
            try:
                os.makedirs(d, exist_ok=True)
                valid_dirs.append(d)
            except Exception:
                print(f"[RT-MONITOR] Impossible de créer/surveiller {d}")
        else:
            valid_dirs.append(d)

    if not valid_dirs:
        print("[RT-MONITOR] Aucun dossier en cours de surveillance. Arrêt.")
        return

    if SYSTEM == "Windows":
        # Windows : utiliser watchdog
        watch_directories_watchdog(valid_dirs)
    else:
        # Linux : inotifywait si disponible, sinon polling
        has_inotify = subprocess.call(
            ["which", "inotifywait"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ) == 0
        watch_func = watch_directory_inotify if has_inotify else watch_directory_polling

        if not has_inotify:
            print("[!] inotify-tools n'est pas installé. Passage en mode POLLING (moins efficace).")

        threads = []
        for d in valid_dirs:
            t = threading.Thread(target=watch_func, args=(d,), daemon=True)
            t.start()
            threads.append(t)

        print("=" * 45)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[RT-MONITOR] Arrêt du moniteur.")


if __name__ == "__main__":
    start_monitoring()
