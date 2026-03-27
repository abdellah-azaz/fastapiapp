import smtplib
import os
import io
import qrcode
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.utils import formatdate, make_msgid
from dotenv import load_dotenv

# Chemin absolu vers le fichier .env
ENV_PATH = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

def send_password_email(receiver_email: str, fullname: str, encrypted_password: str):
    """
    Génère un QR code du mot de passe chiffré et l'envoie par email.
    """
    # Récupération des variables
    host = os.environ.get("SMTP_HOST", "mail.ahdigital.tech")
    port = int(os.environ.get("SMTP_PORT", "465"))
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASS", "")

    if not user or not password:
        print(f"DEBUG: Tentative de chargement depuis {ENV_PATH}")
        print(f"Erreur: SMTP_USER ou SMTP_PASS non configuré. USER='{user}'")
        return False

    # 1. Générer le QR Code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(encrypted_password)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Sauvegarder l'image en mémoire
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()

    # 2. Créer le message MIME Complexe (Alternative pour le texte + Related pour l'image)
    message = MIMEMultipart("alternative")
    message["From"] = f"AH Digital Security <{user}>"
    message["To"] = receiver_email
    message["Subject"] = "🔐 Votre clé de sécurité personnelle (Action requise)"
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()
    message["Auto-Submitted"] = "auto-generated"
    message["X-Auto-Response-Suppress"] = "All"

    # Version Texte Brut (très important pour le score anti-spam)
    text_plain = f"""
    Bonjour {fullname},

    Un nouveau mot de passe a été généré pour votre compte de sécurité. 
    Pour des raisons de confidentialité, ce mot de passe est transmis exclusivement sous forme de Code QR.

    COMMENT RÉCUPÉRER VOTRE MOT DE PASSE :
    1. Ouvrez votre application de gestion de mots de passe sur votre terminal mobile.
    2. Utilisez la fonction de scan.
    3. Scannez le code QR présent dans la version HTML de ce message.

    Note : Si vous ne voyez pas d'image, assurez-vous que votre client mail autorise l'affichage des images.
    Ceci est un message automatique, merci de ne pas y répondre directement.

    L'équipe de sécurité AH Digital.
    """

    # Corps HTML de l'email (Enrichi pour un meilleur ratio texte/image)
    html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; border: 1px solid #eee; padding: 20px;">
          <h2 style="color: #2c3e50;">Sécurisation de votre compte</h2>
          <p>Bonjour <strong>{fullname}</strong>,</p>
          <p>Dans le cadre de notre protocole de sécurité renforcée, nous avons généré une nouvelle clé d'accès pour votre profil.</p>
          
          <div style="background-color: #f9f9f9; border-left: 4px solid #3498db; padding: 15px; margin: 20px 0;">
            <strong>Instructions :</strong><br>
            Veuillez scanner le code QR ci-dessous à l'aide de votre application dédiée pour importer votre nouveau mot de passe.
          </div>

          <div style="text-align: center; margin: 30px 0;">
            <img src="cid:qrcode_image" alt="QR Code de sécurité" style="border: 2px solid #333; padding: 10px; border-radius: 5px;">
            <p style="font-size: 12px; color: #7f8c8d;">Identifiant unique de session : {message['Message-ID']}</p>
          </div>

          <p style="font-size: 13px;">
            <em><strong>Note de sécurité :</strong> Ce code contient vos informations sous forme chiffrée. 
            Il est à usage unique et ne doit jamais être partagé par un autre canal que celui-ci.</em>
          </p>
          
          <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="font-size: 12px; color: #95a5a6; text-align: center;">
            Ceci est un message généré automatiquement par le système AH Digital.<br>
            Si vous n'êtes pas à l'origine de cette demande, veuillez contacter votre administrateur immédiatement.
          </p>
        </div>
      </body>
    </html>
    """
    
    # On crée la structure Related pour intégrer l'image dans le HTML
    msg_related = MIMEMultipart("related")
    msg_html = MIMEText(html, "html", "utf-8")
    msg_related.attach(msg_html)

    # Attacher l'image du QR Code au bloc Related
    msg_img = MIMEImage(img_byte_arr)
    msg_img.add_header("Content-ID", "<qrcode_image>")
    msg_img.add_header("Content-Disposition", "inline", filename="qrcode.png")
    msg_related.attach(msg_img)

    # On attache le texte simple et le bloc HTML/Image au message principal
    message.attach(MIMEText(text_plain, "plain", "utf-8"))
    message.attach(msg_related)

    # 3. Envoyer l'email
    try:
        print(f"Envoi sécurisé du QR Code (Délivrabilité optimisée) à {receiver_email}...")
        if port == 465:
            with smtplib.SMTP_SSL(host, port) as server:
                server.login(user, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(host, port) as server:
                server.starttls()
                server.login(user, password)
                server.send_message(message)
        return True
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email à {receiver_email}: {e}")
        return False

def send_reset_code_email(receiver_email: str, fullname: str, reset_code: str):
    """
    Envoie un code de réinitialisation de mot de passe à 6 chiffres.
    """
    host = os.environ.get("SMTP_HOST", "mail.ahdigital.tech")
    port = int(os.environ.get("SMTP_PORT", "465"))
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASS", "")

    if not user or not password:
        return False

    message = MIMEMultipart("alternative")
    message["From"] = f"Crypton Security <{user}>"
    message["To"] = receiver_email
    message["Subject"] = f"🔑 Votre code de réinitialisation : {reset_code}"
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    text_plain = f"Bonjour {fullname},\n\nVotre code de réinitialisation est : {reset_code}\nCe code expirera dans 10 minutes."
    
    html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #333;">
        <div style="max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
          <h2 style="color: #2c3e50;">Réinitialisation de mot de passe</h2>
          <p>Bonjour <strong>{fullname}</strong>,</p>
          <p>Vous avez demandé la réinitialisation de votre mot de passe. Voici votre code de vérification :</p>
          <div style="background: #f1f2f6; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #3498db; margin: 20px 0;">
            {reset_code}
          </div>
          <p style="font-size: 12px; color: #7f8c8d;">Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.</p>
        </div>
      </body>
    </html>
    """

    message.attach(MIMEText(text_plain, "plain", "utf-8"))
    message.attach(MIMEText(html, "html", "utf-8"))

    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port) as server:
                server.login(user, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(host, port) as server:
                server.starttls()
                server.login(user, password)
                server.send_message(message)
        return True
    except Exception as e:
        print(f"Erreur envoi code reset: {e}")
        return False

def send_signup_code_email(receiver_email: str, fullname: str, signup_code: str):
    """
    Envoie un code de vérification pour l'inscription.
    """
    host = os.environ.get("SMTP_HOST", "mail.ahdigital.tech")
    port = int(os.environ.get("SMTP_PORT", "465"))
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASS", "")

    if not user or not password:
        return False

    message = MIMEMultipart("alternative")
    message["From"] = f"Crypton Security <{user}>"
    message["To"] = receiver_email
    message["Subject"] = f"🔐 Votre code de vérification : {signup_code}"
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    text_plain = f"Bonjour {fullname},\n\nVotre code de vérification pour finaliser votre inscription est : {signup_code}\nCe code expirera dans 15 minutes."
    
    html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #333;">
        <div style="max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
          <h2 style="color: #2c3e50;">Vérification de l'email</h2>
          <p>Bonjour <strong>{fullname}</strong>,</p>
          <p>Merci pour votre inscription. Voici votre code pour vérifier votre adresse email et finaliser la création de votre compte :</p>
          <div style="background: #f1f2f6; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #3498db; margin: 20px 0;">
            {signup_code}
          </div>
          <p style="font-size: 12px; color: #7f8c8d;">Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.</p>
        </div>
      </body>
    </html>
    """

    message.attach(MIMEText(text_plain, "plain", "utf-8"))
    message.attach(MIMEText(html, "html", "utf-8"))

    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port) as server:
                server.login(user, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(host, port) as server:
                server.starttls()
                server.login(user, password)
                server.send_message(message)
        return True
    except Exception as e:
        print(f"Erreur envoi code signup: {e}")
        return False

def send_admin_email(receiver_email: str, subject: str, body: str):
    """
    Envoie un email personnalisé depuis l'admin à un utilisateur.
    L'émetteur est toujours SMTP_USER défini dans .env.
    """
    host = os.environ.get("SMTP_HOST", "mail.ahdigital.tech")
    port = int(os.environ.get("SMTP_PORT", "465"))
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASS", "")

    if not user or not password:
        print("Erreur: SMTP_USER ou SMTP_PASS non configuré.")
        return False

    message = MIMEMultipart("alternative")
    message["From"] = f"Crypton Admin <{user}>"
    message["To"] = receiver_email
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    # Texte brut
    text_plain = body

    # Version HTML
    html_body = body.replace("\n", "<br>")
    html = f"""
    <html>
      <body style="font-family: 'Segoe UI', Arial, sans-serif; color: #e2e8f0; background-color: #0f172a; margin: 0; padding: 0;">
        <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
          <div style="background: linear-gradient(135deg, #1e1b4b, #312e81); padding: 30px; border-radius: 16px; border: 1px solid rgba(139, 92, 246, 0.3);">
            <div style="display: flex; align-items: center; margin-bottom: 24px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 16px;">
              <h2 style="margin: 0; color: #a5b4fc; font-size: 20px;">🛡️ Crypton Administration</h2>
            </div>
            <div style="background: rgba(255,255,255,0.05); padding: 24px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08); line-height: 1.7; font-size: 15px; color: #cbd5e1;">
              {html_body}
            </div>
            <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.08); margin: 24px 0;">
            <p style="font-size: 12px; color: #64748b; text-align: center; margin: 0;">
              Message envoyé par l'administrateur de la plateforme Crypton Security.<br>
              Cet email a été envoyé depuis {user}
            </p>
          </div>
        </div>
      </body>
    </html>
    """

    message.attach(MIMEText(text_plain, "plain", "utf-8"))
    message.attach(MIMEText(html, "html", "utf-8"))

    try:
        print(f"Envoi email admin à {receiver_email}...")
        if port == 465:
            with smtplib.SMTP_SSL(host, port) as server:
                server.login(user, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(host, port) as server:
                server.starttls()
                server.login(user, password)
                server.send_message(message)
        print(f"Email admin envoyé avec succès à {receiver_email}")
        return True
    except Exception as e:
        print(f"Erreur envoi email admin à {receiver_email}: {e}")
        return False

