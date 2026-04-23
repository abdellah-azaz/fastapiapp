import requests
import json

try:
    from config_local import VIRUSTOTAL_API_KEY
except:
    VIRUSTOTAL_API_KEY = ""

def check_virustotal(sha256):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 404:
            return {
                "found": False,
                "message": "Hash inconnu de VirusTotal (fichier jamais analysé)"
            }
        
        if response.status_code != 200:
            return {"found": False, "message": f"Erreur VirusTotal: {response.status_code}"}
        
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        results = data["data"]["attributes"]["last_analysis_results"]
        
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + undetected + stats.get("harmless", 0)
        
        # Famille de menace
        family = "Inconnue"
        for engine, result in results.items():
            if result.get("result") and result.get("category") == "malicious":
                family = result["result"]
                break
        
        # Première détection
        first_seen = data["data"]["attributes"].get("first_submission_date", 0)
        if first_seen:
            from datetime import datetime
            first_seen = datetime.fromtimestamp(first_seen).strftime("%Y-%m-%d")
        
        return {
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "total": total,
            "family": family,
            "first_seen": first_seen,
            "reputation": "Malveillant" if malicious > 0 else "Suspect" if suspicious > 0 else "Propre"
        }
    except Exception as e:
        return {"found": False, "message": f"Erreur: {str(e)}"}
