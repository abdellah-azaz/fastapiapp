#!/bin/bash
echo "AV-Shield — Installation..."
mkdir -p database quarantine reports logs
sqlite3 database/avshield.db "
CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, target_path TEXT, total_files INTEGER DEFAULT 0, clean_files INTEGER DEFAULT 0, suspicious_files INTEGER DEFAULT 0, malware_files INTEGER DEFAULT 0, scan_duration REAL DEFAULT 0, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS threats (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, filename TEXT, filepath TEXT, result TEXT, threat TEXT, sha256 TEXT, heuristic_score INTEGER DEFAULT 0, entropy REAL DEFAULT 0, quarantined INTEGER DEFAULT 0, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS quarantine (id INTEGER PRIMARY KEY AUTOINCREMENT, original_path TEXT, quarantine_file TEXT, threat TEXT, sha256 TEXT, filesize INTEGER DEFAULT 0, restored INTEGER DEFAULT 0, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, target TEXT, user TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
"
echo "Base de donnees creee !"
echo "Maintenant lance : make && python3 web/app.py"
