import platform
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)

if platform.system() == "Windows":
    DB_PATH        = os.path.join(ROOT_DIR, "database", "avshield.db")
    QUARANTINE_DIR = os.path.join(ROOT_DIR, "quarantine")
    REPORTS_DIR    = os.path.join(ROOT_DIR, "reports")
    AVSHIELD_BIN   = os.path.join(ROOT_DIR, "avshield.exe")
else:
    DB_PATH        = os.path.join(ROOT_DIR, "database", "avshield.db")
    QUARANTINE_DIR = os.path.join(ROOT_DIR, "quarantine")
    REPORTS_DIR    = os.path.join(ROOT_DIR, "reports")
    AVSHIELD_BIN   = os.path.join(ROOT_DIR, "avshield")

from flask import send_from_directory, Flask, render_template, request, jsonify
from flask_cors import CORS
import subprocess
import sqlite3
import json

app = Flask(__name__)
CORS(app)

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

@app.route("/")
def index():
    try:
        db = get_db()
        stats = {
            "total_scans"     : db.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            "total_threats"   : db.execute("SELECT COUNT(*) FROM threats").fetchone()[0],
            "total_quarantine": db.execute("SELECT COUNT(*) FROM quarantine WHERE restored=0").fetchone()[0],
            "total_clean"     : db.execute("SELECT SUM(clean_files) FROM scans").fetchone()[0] or 0,
            "total_suspicious": db.execute("SELECT SUM(suspicious_files) FROM scans").fetchone()[0] or 0,
            "total_malware"   : db.execute("SELECT SUM(malware_files) FROM scans").fetchone()[0] or 0
        }
        scans   = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 5").fetchall()
        threats = db.execute("SELECT * FROM threats ORDER BY id DESC LIMIT 5").fetchall()
        db.close()
        return render_template("index.html", stats=stats, scans=scans, threats=threats)
    except Exception as e:
        return render_template("index.html", stats={"total_scans":0,"total_threats":0,"total_quarantine":0,"total_clean":0}, scans=[], threats=[])

@app.route("/scan")
def scan_page():
    return render_template("scan.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json()
    if not data or "path" not in data:
        return jsonify({"error": "Chemin manquant"}), 400
    path      = data["path"].strip()
    auto      = bool(data.get("auto", False))
    want_json = bool(data.get("report", False))
    want_html = bool(data.get("html", False))
    if not data.get("realtime"):
        auto = True
    if not os.path.exists(path):
        filename = os.path.basename(path)
        if os.path.exists(QUARANTINE_DIR):
            for f in os.listdir(QUARANTINE_DIR):
                if filename in f:
                    return jsonify({"success": True, "message": "Fichier deja isole en quarantaine", "quarantine_file": f})
        return jsonify({"error": f"Chemin introuvable: {path}"}), 400
    if not os.path.exists(AVSHIELD_BIN):
        return jsonify({"error": f"Binaire introuvable: {AVSHIELD_BIN}"}), 500
    cmd = [AVSHIELD_BIN, "scan", path, "--report"]
    if auto:
        cmd.append("--auto")
    if want_html:
        cmd.append("--html")
    try:
        import time as _time
        scan_start_time = _time.time()
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN)))
        result_stdout = proc.stdout.decode('utf-8', errors='ignore') if proc.stdout else ''
        result_stderr = proc.stderr.decode('utf-8', errors='ignore') if proc.stderr else ''
        _time.sleep(1.5)
        json_path = None
        json_file = None
        scan_start = scan_start_time - 2
        json_candidates = [os.path.join(REPORTS_DIR, f) for f in os.listdir(REPORTS_DIR) if f.startswith("RPT_") and f.endswith(".json") and os.path.getmtime(os.path.join(REPORTS_DIR, f)) > scan_start]
        if json_candidates:
            json_path = max(json_candidates, key=os.path.getmtime)
            json_file = os.path.basename(json_path)
        html_file = None
        html_reports = [f for f in os.listdir(REPORTS_DIR) if f.startswith("RPT_") and f.endswith(".html")]
        if html_reports:
            html_file = os.path.basename(max((os.path.join(REPORTS_DIR, f) for f in html_reports), key=os.path.getmtime))
        quarantined = False
        quarantine_file = None
        base = os.path.basename(path)
        if os.path.exists(QUARANTINE_DIR):
            for f in os.listdir(QUARANTINE_DIR):
                if f.endswith(".quar") and base in f:
                    quarantined = True
                    quarantine_file = f
                    break
        report_data = None
        if json_path and os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw = f.read()
                # Corriger les backslashes Windows dans le JSON
                import re as _re
                raw = _re.sub(r'(?<!\\)\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})', r'\\\\', raw)
                report_data = json.loads(raw)
            except Exception as _je:
                print(f"[JSON ERROR] {_je}")
                report_data = None
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from email_notifier import send_threat_alert
            if report_data and report_data.get("files"):
                for fi in report_data["files"]:
                    if fi.get("result") in ["MALWARE", "SUSPICIOUS"]:
                        send_threat_alert(fi.get("filename",""), fi.get("filepath",""), fi.get("result",""), fi.get("threat",""), fi.get("heuristic_score",0), fi.get("entropy",0), fi.get("sha256",""))
        except Exception as _e:
            print(f"[EMAIL] {_e}")
        return jsonify({"success": True, "output": result_stdout, "errors": result_stderr, "quarantined": quarantined, "quarantine_file": quarantine_file, "report_json_file": json_file, "report_html_file": html_file, "report_json_url": f"/reports/download/{json_file}" if json_file else None, "report_html_url": f"/reports/{html_file}" if html_file else None, "report": report_data})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timeout (5 min)"}), 408
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/reports-page")
def reports_page():
    return render_template("reports.html")

@app.route("/quarantine")
def quarantine_page():
    try:
        db    = get_db()
        files = db.execute("SELECT * FROM quarantine WHERE restored=0 ORDER BY id DESC").fetchall()
        db.close()
        return render_template("quarantine.html", files=files)
    except:
        return render_template("quarantine.html", files=[])

@app.route("/api/quarantine", methods=["GET"])
def api_quarantine_list():
    try:
        db    = get_db()
        files = db.execute("SELECT * FROM quarantine WHERE restored=0").fetchall()
        db.close()
        return jsonify([dict(f) for f in files])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/quarantine/restore", methods=["POST"])
def api_restore():
    data = request.get_json()
    if not data or "name" not in data:
        return jsonify({"error": "Nom manquant"}), 400
    try:
        result = subprocess.run([AVSHIELD_BIN, "quarantine", "restore", data["name"]], capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN)))
        return jsonify({"success": True, "output": result.stdout})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/quarantine/delete", methods=["POST"])
def api_delete():
    data = request.get_json()
    if not data or "name" not in data:
        return jsonify({"error": "Nom manquant"}), 400
    try:
        result = subprocess.run([AVSHIELD_BIN, "quarantine", "delete", data["name"]], capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN)))
        return jsonify({"success": True, "output": result.stdout})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/stats", methods=["GET"])
def api_stats():
    try:
        db = get_db()
        stats = {"total_scans": db.execute("SELECT COUNT(*) FROM scans").fetchone()[0], "total_threats": db.execute("SELECT COUNT(*) FROM threats").fetchone()[0], "total_quarantine": db.execute("SELECT COUNT(*) FROM quarantine WHERE restored=0").fetchone()[0], "total_clean": db.execute("SELECT SUM(clean_files) FROM scans").fetchone()[0] or 0, "total_malware": db.execute("SELECT SUM(malware_files) FROM scans").fetchone()[0] or 0, "total_suspicious": db.execute("SELECT SUM(suspicious_files) FROM scans").fetchone()[0] or 0}
        db.close()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/history", methods=["GET"])
def api_history():
    try:
        db    = get_db()
        scans = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 20").fetchall()
        db.close()
        return jsonify([dict(s) for s in scans])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports", methods=["GET"])
def api_reports():
    try:
        reports = []
        if os.path.exists(REPORTS_DIR):
            for f in os.listdir(REPORTS_DIR):
                reports.append({"name": f, "path": os.path.join(REPORTS_DIR, f), "size": os.path.getsize(os.path.join(REPORTS_DIR, f))})
        return jsonify(reports)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/reports/<path:filename>")
def open_report(filename):
    return send_from_directory(REPORTS_DIR, filename)

@app.route("/reports/download/<path:filename>")
def download_report(filename):
    return send_from_directory(REPORTS_DIR, filename, as_attachment=False)

@app.route("/api/ai-analyze", methods=["POST"])
def ai_analyze():
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from ai_analyzer import analyze_threat
        data            = request.get_json()
        analysis        = analyze_threat(data.get("filename",""), data.get("result",""), data.get("threat_name",""), data.get("heuristic_score",0), data.get("entropy",0))
        return jsonify({"success": True, "analysis": analysis})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/realtime-events")
def realtime_events():
    events_file = os.path.normpath(os.path.join(BASE_DIR, "..", "database", "realtime_events.json"))
    if os.path.exists(events_file):
        with open(events_file) as f:
            events = json.load(f)
    else:
        events = []
    return jsonify(events)

@app.route("/api/threat-intel", methods=["POST"])
def threat_intel():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from threat_intelligence import check_virustotal
    data   = request.get_json()
    sha256 = data.get("sha256", "")
    if not sha256:
        return jsonify({"error": "SHA256 manquant"}), 400
    return jsonify(check_virustotal(sha256))

if __name__ == "__main__":
    print(f"\n Shield AV-Shield Web Interface")
    print(f"{'='*40}")
    print(f"Systeme : {platform.system()}")
    print(f"Binaire : {AVSHIELD_BIN}")
    print(f"URL     : http://localhost:5000")
    print(f"{'='*40}\n")
    app.run(debug=False, host="0.0.0.0", port=5000)
