import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

try:
    from config_local import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, ALERT_EMAIL
except:
    SMTP_HOST = "sandbox.smtp.mailtrap.io"
    SMTP_PORT = 2525
    SMTP_USER = ""
    SMTP_PASS = ""
    ALERT_EMAIL = ""

def send_threat_alert(filename, filepath, result, threat, heuristic_score, entropy, sha256):
    if not SMTP_USER:
        return False
    try:
        color = "#ff0000" if result == "MALWARE" else "#ffa502"
        icon  = "☠️" if result == "MALWARE" else "⚠️"
        
        html = f"""
        <html><body style="font-family:Arial;background:#f5f5f5;padding:20px;">
        <div style="max-width:600px;margin:0 auto;background:white;border-radius:12px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,0.1);">
          <div style="background:#1a1a2e;padding:20px;text-align:center;">
            <h1 style="color:white;margin:0;">🛡️ AV-Shield — Alerte Sécurité</h1>
          </div>
          <div style="padding:25px;">
            <div style="background:{color};color:white;padding:15px;border-radius:8px;text-align:center;margin-bottom:20px;">
              <h2 style="margin:0;">{icon} {result} DÉTECTÉ</h2>
            </div>
            <table style="width:100%;border-collapse:collapse;">
              <tr style="background:#f8f9fa;"><td style="padding:10px;font-weight:bold;">📁 Fichier</td><td style="padding:10px;">{filename}</td></tr>
              <tr><td style="padding:10px;font-weight:bold;">📂 Chemin</td><td style="padding:10px;">{filepath}</td></tr>
              <tr style="background:#f8f9fa;"><td style="padding:10px;font-weight:bold;">🦠 Menace</td><td style="padding:10px;">{threat or 'Inconnue'}</td></tr>
              <tr><td style="padding:10px;font-weight:bold;">📊 Score heuristique</td><td style="padding:10px;">{heuristic_score}/100</td></tr>
              <tr style="background:#f8f9fa;"><td style="padding:10px;font-weight:bold;">📈 Entropie</td><td style="padding:10px;">{entropy}/8</td></tr>
              <tr><td style="padding:10px;font-weight:bold;">🔑 SHA256</td><td style="padding:10px;font-size:0.85em;">{sha256}</td></tr>
              <tr style="background:#f8f9fa;"><td style="padding:10px;font-weight:bold;">📅 Date</td><td style="padding:10px;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
            </table>
            <div style="margin-top:20px;padding:15px;background:#fff3cd;border-radius:8px;border-left:4px solid #ffc107;">
              <b>⚠️ Action recommandée :</b> Vérifiez immédiatement ce fichier dans l'interface AV-Shield et prenez les mesures nécessaires.
            </div>
          </div>
          <div style="background:#1a1a2e;padding:15px;text-align:center;">
            <p style="color:#888;margin:0;font-size:0.85em;">AV-Shield — Système de détection multi-couches avec IA</p>
          </div>
        </div>
        </body></html>
        """
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 AV-Shield Alert — {result} détecté : {filename}"
        msg['From'] = SMTP_USER
        msg['To'] = ALERT_EMAIL
        msg.attach(MIMEText(html, 'html'))
        
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, ALERT_EMAIL, msg.as_string())
        
        print(f"[EMAIL] Alerte envoyée pour {filename}")
        return True
    except Exception as e:
        print(f"[EMAIL] Erreur: {e}")
        return False
