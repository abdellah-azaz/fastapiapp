import os
import base64
from ai_analyzer import analyze_threat
import secrets
import string
import mysql.connector
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException, UploadFile, File, Query
from pydantic import BaseModel
from contextlib import asynccontextmanager
from mail import send_password_email, send_reset_code_email, send_signup_code_email, send_admin_email
from dotenv import load_dotenv
import platform
import subprocess
import json
import sys
from passlib.context import CryptContext
import uuid
import shutil
from pathlib import Path
from fastapi.responses import StreamingResponse
import io
import random
import time
import signal

from fastapi.middleware.cors import CORSMiddleware

# Global variable to store the monitor process
monitor_process = None


# Simulation d'un stockage de codes (En prod, utiliser Redis/DB avec expiration)
reset_codes = {} # {email: {"code": str, "expires": float}}
signup_codes = {} # {email: {"code": str, "expires": float}}

# Configuration du hachage des mots de passe
# Configuration du hachage des mots de passe (plus compatible que bcrypt sur certains environnements)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Charger les variables d'environnement
load_dotenv()

# --- Configuration ---
SECRET_KEY_HEX = os.environ.get("SECRET_KEY", "7072e9d2a23e8093d3b769ea8736a53697eb2f75a6435c43d81b95f27c706900")
SECRET_KEY = bytes.fromhex(SECRET_KEY_HEX)

# Nonce fixe (pour le développement/tests selon demande utilisateur)
FIXED_NONCE_HEX = os.environ.get("FIXED_NONCE_HEX", "f1e2d3c4b5a69788796a5b4c")
FIXED_NONCE = bytes.fromhex(FIXED_NONCE_HEX)

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASS", ""),
    "database": os.environ.get("DB_NAME", "passworddb")
}

# --- Configuration Vault ---
STORAGE_DIR = Path("storage/encrypted")
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# --- Database Management ---
def init_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INT AUTO_INCREMENT PRIMARY KEY,
                psswrd TEXT NOT NULL,
                owner_email VARCHAR(255)
            )
        """)
        
        # Ensure owner_email exists in existing tables
        tables_to_migrate = [
            ("members", "owner_email", "VARCHAR(255)"),
            ("passwords", "owner_email", "VARCHAR(255)")
        ]
        for table, col, col_def in tables_to_migrate:
            try:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
                print(f"Added column {col} to {table}.")
            except mysql.connector.Error as err:
                if err.errno != 1060: # Duplicate column name
                    print(f"Error migrating {table}: {err}")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS members (
                id INT AUTO_INCREMENT PRIMARY KEY,
                fullname VARCHAR(255) NOT NULL,
                mail VARCHAR(255) NOT NULL,
                owner_email VARCHAR(255)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mainuser (
                id INT AUTO_INCREMENT PRIMARY KEY,
                fullname VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                telephone VARCHAR(20),
                password VARCHAR(255) NOT NULL,
                is_superadmin BOOLEAN DEFAULT FALSE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault_files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                file_id VARCHAR(255) NOT NULL,
                filename VARCHAR(255) NOT NULL,
                encryption_key TEXT NOT NULL,
                owner_email VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flutter_noti (
                id INT AUTO_INCREMENT PRIMARY KEY,
                noti VARCHAR(255) NOT NULL,
                owner_email VARCHAR(255) NOT NULL,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flutter_pass (
                id INT AUTO_INCREMENT PRIMARY KEY,
                password VARCHAR(255) NOT NULL,
                owner_email VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_settings (
                email VARCHAR(255) PRIMARY KEY,
                random_password_enabled BOOLEAN DEFAULT TRUE,
                encrypted_result_visible BOOLEAN DEFAULT TRUE,
                scan_history_cleanup_mode VARCHAR(50) DEFAULT 'Jamais',
                use_custom_restore_path BOOLEAN DEFAULT FALSE,
                custom_restore_path TEXT,
                is_ai_analysis_enabled BOOLEAN DEFAULT TRUE,
                is_realtime_analysis_enabled BOOLEAN DEFAULT TRUE,
                require_password_for_delete BOOLEAN DEFAULT TRUE,
                require_password_for_download BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (email) REFERENCES mainuser(email) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS av_scan_mappings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                scan_id VARCHAR(255) NOT NULL,
                filename TEXT NOT NULL,
                owner_email VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX (owner_email),
                INDEX (scan_id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS banned_users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                reason TEXT,
                banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (email) REFERENCES mainuser(email) ON DELETE CASCADE
            )
        """)
        conn.commit()
        # Ensure new columns exist for existing tables
        new_columns = [
            ("is_ai_analysis_enabled", "BOOLEAN DEFAULT TRUE"),
            ("is_realtime_analysis_enabled", "BOOLEAN DEFAULT TRUE"),
            ("require_password_for_delete", "BOOLEAN DEFAULT TRUE"),
            ("require_password_for_download", "BOOLEAN DEFAULT TRUE")
        ]
        for col_name, col_def in new_columns:
            try:
                cursor.execute(f"ALTER TABLE user_settings ADD COLUMN {col_name} {col_def}")
                print(f"Added column {col_name} to user_settings.")
            except mysql.connector.Error as err:
                if err.errno != 1060: # Duplicate column name
                    print(f"Error adding column {col_name} to user_settings: {err}")
        
        # Migration for mainuser table
        try:
            cursor.execute("ALTER TABLE mainuser ADD COLUMN is_superadmin BOOLEAN DEFAULT FALSE")
            print("Added column is_superadmin to mainuser.")
        except mysql.connector.Error as err:
            if err.errno != 1060: # Duplicate column name
                print(f"Error adding column is_superadmin to mainuser: {err}")
        conn.commit()
        cursor.close()
        conn.close()
        print("Database initialized successfully.")
    except mysql.connector.Error as err:
        print(f"Error: {err}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    global monitor_process
    # Startup: Initialize the database
    init_db()
    
    # Démarrage automatique du moniteur temps réel
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        monitor_script = os.path.join(base_dir, "realtime_monitor.py")
        if os.path.exists(monitor_script):
            print(f"🚀 Démarrage automatique du moniteur : {monitor_script}")
            monitor_process = subprocess.Popen([sys.executable, monitor_script])
        else:
            print(f"⚠️ Moniteur introuvable à {monitor_script}")
    except Exception as e:
        print(f"❌ Erreur lors du lancement du moniteur : {e}")

    yield
    
    # Shutdown: Arrêter le moniteur
    if monitor_process and monitor_process.poll() is None:
        print("🛑 Arrêt du moniteur temps réel...")
        monitor_process.terminate()
        try:
            monitor_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            monitor_process.kill()

# --- Application FastAPI ---
app = FastAPI(
    title="Crypton API",
    description="Une API simple pour chiffrer et déchiffrer des messages avec AES-GCM et les stocker en base de données.",
    version="1.1.0",
    lifespan=lifespan
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # En production, spécifier l'URL exacte du front
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Modèles de données ---
class EncryptRequest(BaseModel):
    text: str
    owner_email: str

class FlutterPasswords(BaseModel):
    password: str
    owner_email: str

class DecryptRequest(BaseModel):
    blob: str
    owner_email: str

class CryptoResponse(BaseModel):
    result: str

class PasswordGenerateRequest(BaseModel):
    owner_email: str

class MemberRequest(BaseModel):
    fullname: str
    mail: str
    owner_email: str

class FlutterNoti(BaseModel):
    noti :str
    owner_email:str

class AIExplainRequest(BaseModel):
    filename: str
    result: str
    threat_name: str | None = None
    heuristic_score: int
    entropy: float

class MemberResponse(BaseModel):
    id: int
    fullname: str
    mail: str
    message: str | None = None

class MemberListResponse(BaseModel):
    members: list[MemberResponse]
    count: int

class SendPasswordRequest(BaseModel):
    password: str
    member_ids: list[int]

class ScannerAVRequest(BaseModel):
    path: str
    owner_email: str
    auto: bool = False
    report: bool = True
    html: bool = False

class SignupCodeRequest(BaseModel):
    fullname: str
    email: str

class SignupRequest(BaseModel):
    fullname: str
    email: str
    telephone: str | None = None
    password: str
    code: str

class LoginRequest(BaseModel):
    email: str
    password: str

class UpdatePasswordRequest(BaseModel):
    email: str
    old_password: str
    new_password: str

class UpdateProfileRequest(BaseModel):
    email: str
    fullname: str
    telephone: str | None = None

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    email: str
    code: str
    new_password: str

class AuthResponse(BaseModel):
    success: bool
    message: str
    user: dict | None = None

class UserSettings(BaseModel):
    email: str
    random_password_enabled: bool = True
    encrypted_result_visible: bool = True
    scan_history_cleanup_mode: str = "Jamais"
    use_custom_restore_path: bool = False
    custom_restore_path: str = ""
    is_ai_analysis_enabled: bool = True
    is_realtime_analysis_enabled: bool = True
    require_password_for_delete: bool = True
    require_password_for_download: bool = True

class BanRequest(BaseModel):
    user_email: str
    email: str
    reason: str | None = None

class UnbanRequest(BaseModel):
    user_email: str
    email: str

class AdminEmailRequest(BaseModel):
    email: str  # admin email (requester)
    to_email: str  # recipient
    subject: str
    body: str


# --- Logique Vault ---

def vault_encrypt_file(file_content: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Chiffre le contenu d'un fichier.
    Retourne (key, nonce, ciphertext)
    """
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, file_content, None)
    return key, nonce, ciphertext

def vault_decrypt_file(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Déchiffre le contenu d'un fichier.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# --- Logique de chiffrement ---
def chiffrer(texte: str) -> str:
    """Chiffre un texte en utilisant AES-GCM avec un nonce fixe."""
    nonce = FIXED_NONCE
    aesgcm = AESGCM(SECRET_KEY)
    chiffre = aesgcm.encrypt(nonce, texte.encode(), None)
    return base64.b64encode(nonce + chiffre).decode()

def dechiffrer(blob: str) -> str:
    """Déchiffre un blob base64 encodé."""
    try:
        data = base64.b64decode(blob)
        if len(data) < 12:
            raise ValueError("Données corrompues ou invalides")
        nonce, chiffre = data[:12], data[12:]
        aesgcm = AESGCM(SECRET_KEY)
        return aesgcm.decrypt(nonce, chiffre, None).decode()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erreur de déchiffrement: {str(e)}")

# --- Utilitaires Auth ---
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def save_to_db(encrypted_text: str, owner_email: str):
    """Enregistre le mot de passe chiffré dans MySQL."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO passwords (psswrd, owner_email) VALUES (%s, %s)", (encrypted_text, owner_email))
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")

# --- Routes API ---
@app.post("/encrypt", response_model=CryptoResponse)
async def encrypt_endpoint(request: EncryptRequest):
    """
    Chiffre le texte fourni et l'enregistre dans la base de données.
    """
    resultat = chiffrer(request.text)
    save_to_db(resultat, request.owner_email)
    return CryptoResponse(result=resultat)

@app.post("/decrypt", response_model=CryptoResponse)
async def decrypt_endpoint(request: DecryptRequest):
    """
    Déchiffre le blob fourni dans la requête.
    """
    resultat = dechiffrer(request.blob)
    return CryptoResponse(result=resultat)

@app.post("/members", response_model=MemberResponse)
async def add_member_endpoint(member: MemberRequest):
    """
    Ajoute un nouveau membre dans la base de données.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        query = "INSERT INTO members (fullname, mail, owner_email) VALUES (%s, %s, %s)"
        cursor.execute(query, (member.fullname, member.mail, member.owner_email))
        conn.commit()
        member_id = cursor.lastrowid
        cursor.close()
        conn.close()
        return MemberResponse(
            id=member_id,
            fullname=member.fullname,
            mail=member.mail,
            message="Membre ajouté avec succès !"
        )
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")

@app.post("/notifications", response_model=dict)
async def add_noti(notification: FlutterNoti):
    """
    Ajoute une nouvelle notification dans la base de données.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        query = "INSERT INTO flutter_noti (noti, owner_email) VALUES (%s, %s)"
        cursor.execute(query, (notification.noti, notification.owner_email))
        conn.commit()
        
        noti_id = cursor.lastrowid
        
        cursor.close()
        conn.close()
        
        return {
            "id": noti_id,
            "noti": notification.noti,
            "owner_email": notification.owner_email,
            "message": "Notification ajoutée avec succès !"
        }
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")

@app.post("/flutterPassword", response_model=dict)
async def add_flutter_password(flutter_pass: FlutterPasswords):
    """
    Ajoute un mot de passe Flutter dans la base de données.
    """
    try:
        # Connexion à la base de données
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
       
        
        # Insertion du nouveau mot de passe Flutter
        query = "INSERT INTO flutter_pass (password, owner_email) VALUES (%s, %s)"
        cursor.execute(query, (flutter_pass.password, flutter_pass.owner_email))
        conn.commit()
        
        # Récupération de l'ID généré
        flutter_id = cursor.lastrowid
        
        cursor.close()
        conn.close()
        
        # Retourner une réponse de succès
        return {
            "id": flutter_id,
            "message": "Mot de passe Flutter ajouté avec succès !",
            "owner_email": flutter_pass.owner_email
        }
        
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")


@app.get("/flutterPassword/history/{owner_email}", response_model=dict)
async def get_flutter_password_history(owner_email: str):
    """
    Récupère l'historique complet des mots de passe Flutter pour un email propriétaire donné.
    """
    try:
        # Connexion à la base de données
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # Requête pour récupérer tous les mots de passe d'un propriétaire
        # Triés par date d'insertion (du plus récent au plus ancien)
        query = """
        SELECT id, password, owner_email, created_at 
        FROM flutter_pass 
        WHERE owner_email = %s 
        ORDER BY created_at DESC
        """
        cursor.execute(query, (owner_email,))
        
        # Récupération de tous les résultats
        passwords_history = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        # Vérifier si des mots de passe ont été trouvés
        if not passwords_history:
            return {
                "owner_email": owner_email,
                "message": "Aucun mot de passe trouvé pour cet email",
                "count": 0,
                "passwords": []
            }
        
        # Retourner l'historique complet
        return {
            "owner_email": owner_email,
            "message": f"{len(passwords_history)} mot(s) de passe trouvé(s)",
            "count": len(passwords_history),
            "passwords": passwords_history
        }
        
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")


@app.get("/notifications/{owner_email}", response_model=dict)
async def get_notifications_by_owner(owner_email: str):
    """
    Récupère toutes les notifications pour un email propriétaire donné.
    """
    try:
        # Connexion à la base de données
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # Requête pour récupérer toutes les notifications d'un propriétaire
        # Triées par date de création (du plus récent au plus ancien)
        query = """
        SELECT id, noti, owner_email, created_at 
        FROM flutter_noti 
        WHERE owner_email = %s 
        ORDER BY created_at DESC
        """
        cursor.execute(query, (owner_email,))
        
        # Récupération de tous les résultats
        notifications = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        # Vérifier si des notifications ont été trouvées
        if not notifications:
            return {
                "owner_email": owner_email,
                "message": "Aucune notification trouvée pour cet email",
                "count": 0,
                "notifications": []
            }
        
        # Retourner toutes les notifications
        return {
            "owner_email": owner_email,
            "message": f"{len(notifications)} notification(s) trouvée(s)",
            "count": len(notifications),
            "notifications": notifications
        }
        
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

@app.delete("/flutterPassword/history/{owner_email}", response_model=dict)
async def delete_flutter_password_history(owner_email: str):
    """
    Supprime tout l'historique des mots de passe Flutter pour un email propriétaire donné.
    """
    try:
        # Connexion à la base de données
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Vérifier d'abord si des enregistrements existent
        check_query = "SELECT COUNT(*) FROM flutter_pass WHERE owner_email = %s"
        cursor.execute(check_query, (owner_email,))
        count = cursor.fetchone()[0]
        
        if count == 0:
            cursor.close()
            conn.close()
            return {
                "owner_email": owner_email,
                "message": "Aucun mot de passe trouvé pour cet email",
                "deleted_count": 0
            }
        
        # Supprimer tous les mots de passe de l'utilisateur
        delete_query = "DELETE FROM flutter_pass WHERE owner_email = %s"
        cursor.execute(delete_query, (owner_email,))
        conn.commit()
        
        deleted_count = cursor.rowcount
        
        cursor.close()
        conn.close()
        
        return {
            "owner_email": owner_email,
            "message": f"Historique supprimé avec succès",
            "deleted_count": deleted_count
        }
        
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

@app.get("/members", response_model=MemberListResponse)
async def list_members_endpoint(email: str):
    """
    Récupère la liste de tous les membres.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, fullname, mail FROM members WHERE owner_email = %s", (email,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return MemberListResponse(members=rows, count=len(rows))
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")

@app.get("/members/search", response_model=MemberListResponse)
async def search_members_endpoint(fullname: str, email: str):
    """
    Recherche des membres par leur nom complet (partiel).
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        query = "SELECT id, fullname, mail FROM members WHERE fullname LIKE %s AND owner_email = %s"
        cursor.execute(query, (f"%{fullname}%", email))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return MemberListResponse(members=rows, count=len(rows))
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")

@app.put("/members/{member_id}", response_model=MemberResponse)
async def update_member_endpoint(member_id: int, member: MemberRequest):
    """
    Met à jour les informations d'un membre existant.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        query = "UPDATE members SET fullname = %s, mail = %s WHERE id = %s AND owner_email = %s"
        cursor.execute(query, (member.fullname, member.mail, member_id, member.owner_email))
        conn.commit()
        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Membre non trouvé ou accès refusé")
        cursor.close()
        conn.close()
        return MemberResponse(
            id=member_id,
            fullname=member.fullname,
            mail=member.mail,
            message="Membre mis à jour avec succès !"
        )
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")

@app.delete("/members/{member_id}")
async def delete_member_endpoint(member_id: int, email: str):
    """
    Supprime un membre de la base de données.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM members WHERE id = %s AND owner_email = %s", (member_id, email))
        conn.commit()
        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Membre non trouvé ou accès refusé")
        cursor.close()
        conn.close()
        return {"message": "Membre supprimé avec succès !"}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")

@app.post("/generate", response_model=CryptoResponse)
async def generate_password_endpoint(request: PasswordGenerateRequest):
    """
    Génère un mot de passe aléatoire, le chiffre et l'enregistre dans la base de données.
    """
    # Génération d'un mot de passe sécurisé (16 caractères)
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(16))
    
    resultat = chiffrer(password)
    save_to_db(resultat, request.owner_email)
    
    # On retourne le mot de passe en clair ET le chiffré dans un message combiné pour le test
    # ou juste le chiffré selon le besoin. Ici on retourne le chiffré comme demandé, 
    # mais on pourrait ajouter le clair pour que l'utilisateur le voit.
    return CryptoResponse(result=resultat)

@app.post("/members/send-password")
async def send_password_to_members(request: SendPasswordRequest):
    """
    Chiffre un mot de passe et l'envoie par mail à une liste de membres.
    """
    try:
        # 1. Chiffrer le mot de passe
        print(f"DEBUG: Mot de passe à partager : {request.password}")
        encrypted_pw = chiffrer(request.password)
        
        # 2. Récupérer les mails des membres
        if not request.member_ids:
            raise HTTPException(status_code=400, detail="Liste de membres vide")

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # Préparation de la requête avec IN
        format_strings = ','.join(['%s'] * len(request.member_ids))
        cursor.execute(f"SELECT fullname, mail FROM members WHERE id IN ({format_strings})", tuple(request.member_ids))
        members = cursor.fetchall()
        
        if not members:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Aucun membre trouvé avec ces IDs")

        # 3. Envoyer les emails
        sent_count = 0
        for m in members:
            if send_password_email(m["mail"], m["fullname"], encrypted_pw):
                print(f"Email envoyé avec succès à : {m['mail']}")
                sent_count += 1
        
        cursor.close()
        conn.close()
        
        return {
            "message": f"Mot de passe envoyé avec succès à {sent_count}/{len(members)} membres.",
            "encrypted_password": encrypted_pw
        }
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/members/send-plain-password")
async def send_plain_password_to_members(request: SendPasswordRequest):
    """
    Envoie un mot de passe en clair (sans chiffrement) par mail à une liste de membres via un Code QR.
    """
    try:
        # 1. Utiliser le mot de passe en clair directement
        print(f"DEBUG: Mot de passe en clair à partager : {request.password}")
        plain_pw = request.password
        
        # 2. Récupérer les mails des membres
        if not request.member_ids:
            raise HTTPException(status_code=400, detail="Liste de membres vide")

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # Préparation de la requête avec IN
        format_strings = ','.join(['%s'] * len(request.member_ids))
        cursor.execute(f"SELECT fullname, mail FROM members WHERE id IN ({format_strings})", tuple(request.member_ids))
        members = cursor.fetchall()
        
        if not members:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Aucun membre trouvé avec ces IDs")

        # 3. Envoyer les emails avec le mot de passe en clair
        sent_count = 0
        for m in members:
            # Note: send_password_email génère le QR code à partir du 3ème argument
            if send_password_email(m["mail"], m["fullname"], plain_pw):
                print(f"Email (clair) envoyé avec succès à : {m['mail']}")
                sent_count += 1
        
        cursor.close()
        conn.close()
        
        return {
            "message": f"Mot de passe (clair) envoyé avec succès à {sent_count}/{len(members)} membres.",
            "plain_password": plain_pw
        }
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scanner")
async def scan_endpoint():
    """
    Détecte l'OS, lance le scanner approprié et retourne les résultats.
    """
    systeme = platform.system()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    if systeme == "Windows":
        script_path = os.path.join(base_dir, "modules", "Scanner.py")
        result_path = r"C:\AuditAI\data\scan_complet.json"
    elif systeme == "Linux":
        script_path = os.path.join(base_dir, "modules", "linux_scanner.py")
        result_path = "/tmp/AuditAI/data/scan_linux.json"
    else:
        raise HTTPException(status_code=400, detail=f"Système {systeme} non supporté")

    if not os.path.exists(script_path):
        raise HTTPException(status_code=500, detail=f"Script de scan introuvable: {script_path}")

    try:
        # Exécuter le scanner
        process = subprocess.run([sys.executable, script_path], capture_output=True, text=True)
        
        if process.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Erreur lors du scan: {process.stderr}")

        # Lire le fichier résultat
        if not os.path.exists(result_path):
            raise HTTPException(status_code=500, detail="Fichier de résultat non généré")

        with open(result_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        return data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

@app.post("/scannerav")
async def scanner_av_endpoint(request: ScannerAVRequest):
    """
    Lance un scan multi-couches (ClamAV, SHA256, Heuristique, Entropie) via le binaire AV-Shield.
    """
    import re
    import traceback
    
    print(f"DEBUG: Requête scannerav pour le chemin: {request.path}")
    
    # Configuration des chemins relatifs à ce fichier
    base_dir = os.path.dirname(os.path.abspath(__file__))
    av_shield_dir = os.path.join(base_dir, "av-shield")
    av_bin = os.path.join(av_shield_dir, "avshield")
    reports_dir = os.path.join(av_shield_dir, "reports")

    if not os.path.exists(av_bin):
        print(f"ERROR: Binaire AV-Shield introuvable à {av_bin}")
        raise HTTPException(status_code=500, detail=f"Binaire AV-Shield introuvable à {av_bin}")

    # Construction de la commande
    cmd = [av_bin, "scan", request.path]
    if request.report:
        cmd.append("--report")
    if request.html:
        cmd.append("--html")
    if request.auto:
        cmd.append("--auto")

    print(f"DEBUG: Exécution de la commande: {' '.join(cmd)}")

    try:
        # Exécution du binaire C
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=av_shield_dir,
            timeout=300
        )

        print(f"DEBUG: Sortie standard du binaire:\n{process.stdout}")
        if process.stderr:
            print(f"DEBUG: Sortie d'erreur du binaire:\n{process.stderr}")

        # Nettoyage des codes couleur ANSI pour le parsing
        output_clean = re.sub(r'\x1b\[[0-9;]*m', '', process.stdout + process.stderr)
        
        # Recherche du fichier rapport JSON généré
        json_file = None
        # Attention au regex: on cherche "Rapport JSON généré: (reports/)?XXXX.json"
        match = re.search(r'Rapport JSON généré:\s+(?:reports/)?(RPT_[^\s]+\.json)', output_clean)
        if match:
            json_file = match.group(1)
            print(f"DEBUG: Rapport JSON détecté: {json_file}")
        else:
            print("WARNING: Aucun rapport JSON détecté dans la sortie du binaire.")
            # Tentative de récupération du dernier rapport si le fichier est déjà en quarantaine
            if "Chemin introuvable" in output_clean or "not found" in output_clean.lower():
                print(f"DEBUG: Recherche d'un ancien rapport pour {request.path}...")
                try:
                    all_reports = [f for f in os.listdir(reports_dir) if f.endswith(".json")]
                    all_reports.sort(reverse=True) # Trier par date (basé sur le nom RPT_YYYYMMDD_HHMMSS)
                    for r_file in all_reports:
                        with open(os.path.join(reports_dir, r_file), 'r') as f:
                            tmp_data = json.load(f)
                            if tmp_data.get("scan_target") == request.path:
                                json_file = r_file
                                print(f"DEBUG: Ancien rapport trouvé: {json_file}")
                                break
                except Exception as e:
                    print(f"ERROR: Erreur lors de la recherche d'ancien rapport: {e}")
        
        # Lecture du contenu du rapport
        report_data = None
        if json_file:
            json_full_path = os.path.join(reports_dir, json_file)
            print(f"DEBUG: Lecture du rapport à {json_full_path}")
            if os.path.exists(json_full_path):
                try:
                    with open(json_full_path, 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                    print("DEBUG: Rapport JSON chargé avec succès")
                    
                    # Enregistrer le mapping scan_id <-> owner_email
                    try:
                        scan_id = report_data.get("report_id", "UNKNOWN")
                        conn_m = mysql.connector.connect(**DB_CONFIG)
                        cursor_m = conn_m.cursor()
                        cursor_m.execute(
                            "INSERT INTO av_scan_mappings (scan_id, filename, owner_email) VALUES (%s, %s, %s)",
                            (scan_id, request.path, request.owner_email)
                        )
                        conn_m.commit()
                        cursor_m.close()
                        conn_m.close()
                        print(f"DEBUG: Mapping créé pour {scan_id} -> {request.owner_email}")
                    except Exception as me:
                        print(f"ERROR: Erreur création mapping: {me}")
                except Exception as e:
                    print(f"ERROR: Erreur lecture JSON: {e}")
                    traceback.print_exc()
            else:
                print(f"ERROR: Fichier rapport {json_full_path} inexistant après génération supposée.")

        return {
            "success": True,
            "scan_id": report_data.get("report_id") if report_data else "UNKNOWN",
            "output": process.stdout,
            "report": report_data,
            "error_log": process.stderr if process.returncode != 0 else None
        }

    except subprocess.TimeoutExpired:
        print("ERROR: TimeoutExpired lors du scan.")
        raise HTTPException(status_code=408, detail="Le scan a dépassé le temps limite de 5 minutes.")
    except Exception as e:
        print(f"ERROR: Exception lors de scannerav: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erreur lors de l'exécution du scan: {str(e)}")

@app.get("/av/stats")
async def get_av_stats():
    """Récupère et parse les statistiques globales d'AV-Shield"""
    import re
    import traceback
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    av_shield_dir = os.path.join(base_dir, "av-shield")
    av_bin = os.path.join(av_shield_dir, "avshield")

    print("DEBUG: Requête AV Stats")
    try:
        process = subprocess.run([av_bin, "stats"], capture_output=True, text=True, cwd=av_shield_dir)
        
        output = process.stdout
        # Nettoyage des codes ANSI
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', output)
        
        stats = {
            "total_scans": 0,
            "threats_detected": 0,
            "in_quarantine": 0,
            "raw_output": clean_output
        }
        
        # Regex pour extraire les valeurs
        match_scans = re.search(r'Total scans\s+:\s+(\d+)', clean_output)
        match_threats = re.search(r'Menaces détectées:\s+(\d+)', clean_output)
        match_quarantine = re.search(r'En quarantaine\s+:\s+(\d+)', clean_output)
        
        if match_scans: stats["total_scans"] = int(match_scans.group(1))
        if match_threats: stats["threats_detected"] = int(match_threats.group(1))
        if match_quarantine: stats["in_quarantine"] = int(match_quarantine.group(1))
        
        return stats
    except Exception as e:
        print(f"ERROR: Exception dans get_av_stats: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/av/history")
async def get_av_history(email: str):
    """Récupère l'historique des scans via SQLite, filtré par utilisateur"""
    import sqlite3
    import traceback
    db_path = os.path.join(os.path.dirname(__file__), "av-shield", "database", "avshield.db")
    
    print(f"DEBUG: Requête AV History pour {email} (DB: {db_path})")
    if not os.path.exists(db_path):
        print(f"WARNING: Base de données introuvable à {db_path}")
        return []

    try:
        # 1. Récupérer les scan_ids autorisés pour cet email depuis MySQL
        conn_m = mysql.connector.connect(**DB_CONFIG)
        cursor_m = conn_m.cursor()
        cursor_m.execute("SELECT scan_id FROM av_scan_mappings WHERE owner_email = %s", (email,))
        allowed_scan_ids = {row[0] for row in cursor_m.fetchall()}
        cursor_m.close()
        conn_m.close()

        # 2. Récupérer l'historique depuis SQLite
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY scan_date DESC")
        rows = cursor.fetchall()
        
        # 3. Filtrer
        history = [dict(row) for row in rows if row["scan_id"] in allowed_scan_ids]
        conn.close()
        print(f"DEBUG: {len(history)} entrées d'historique trouvées pour {email}")
        return history
    except Exception as e:
        print(f"ERROR: Exception dans get_av_history: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/av/history/cleanup/{days}")
async def cleanup_av_history(days: int, email: str):
    """Supprime les entrées de l'historique plus vieilles que X jours"""
    import sqlite3
    import traceback
    from datetime import datetime, timedelta

    db_path = os.path.join(os.path.dirname(__file__), "av-shield", "database", "avshield.db")
    print(f"DEBUG: Requête Cleanup AV History (jours: {days}, DB: {db_path})")
    
    if not os.path.exists(db_path):
        return {"success": False, "message": "Base de données introuvable"}

    try:
        # 1. Récupérer les scan_ids de l'utilisateur à nettoyer
        conn_m = mysql.connector.connect(**DB_CONFIG)
        cursor_m = conn_m.cursor()
        
        limit_date_dt = datetime.now() - timedelta(days=days) if days >= 0 else datetime.min
        
        if days < 0:
            cursor_m.execute("SELECT scan_id FROM av_scan_mappings WHERE owner_email = %s", (email,))
        else:
            cursor_m.execute("SELECT scan_id FROM av_scan_mappings WHERE owner_email = %s AND created_at < %s", (email, limit_date_dt))
            
        target_scan_ids = [row[0] for row in cursor_m.fetchall()]
        
        if not target_scan_ids:
            cursor_m.close()
            conn_m.close()
            return {"success": True, "message": "Rien à nettoyer.", "deleted_count": 0}

        # 2. Nettoyer dans SQLite
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        format_strings = ','.join(['?'] * len(target_scan_ids))
        cursor.execute(f"DELETE FROM scans WHERE report_id IN ({format_strings})", tuple(target_scan_ids))
        cursor.execute(f"DELETE FROM threats WHERE scan_id IN ({format_strings})", tuple(target_scan_ids))
        
        count = cursor.rowcount
        conn.commit()
        conn.close()

        # 3. Nettoyer les mappings dans MySQL
        if days < 0:
            cursor_m.execute("DELETE FROM av_scan_mappings WHERE owner_email = %s", (email,))
        else:
            cursor_m.execute("DELETE FROM av_scan_mappings WHERE owner_email = %s AND created_at < %s", (email, limit_date_dt))
        
        conn_m.commit()
        cursor_m.close()
        conn_m.close()
        
        return {"success": True, "message": f"Nettoyage effectué pour {email}.", "deleted_count": count}
    except Exception as e:
        print(f"ERROR: Exception dans cleanup_av_history: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/av/quarantine")
async def get_av_quarantine(email: str):
    """Récupère la liste des fichiers en quarantaine, filtrée par utilisateur"""
    import sqlite3
    import traceback
    db_path = os.path.join(os.path.dirname(__file__), "av-shield", "database", "avshield.db")

    print(f"DEBUG: Requête AV Quarantine pour {email} (DB: {db_path})")
    if not os.path.exists(db_path):
        print(f"WARNING: Base de données introuvable à {db_path}")
        return []

    try:
        # 1. Récupérer les fichiers/scans autorisés pour cet email depuis MySQL
        conn_m = mysql.connector.connect(**DB_CONFIG)
        cursor_m = conn_m.cursor()
        # On peut filtrer soit par scan_id soit par filename (ici scan_id est plus précis)
        cursor_m.execute("SELECT scan_id, filename FROM av_scan_mappings WHERE owner_email = %s", (email,))
        allowed_mappings = cursor_m.fetchall()
        allowed_filenames = {row[1] for row in allowed_mappings}
        cursor_m.close()
        conn_m.close()

        # 2. Récupérer la quarantaine depuis SQLite
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM quarantine WHERE restored = 0 ORDER BY quarantine_date DESC")
        rows = cursor.fetchall()
        
        # 3. Filtrer par nom de fichier (attention aux chemins complets vs noms de fichiers simples)
        items = []
        for row in rows:
            # Si le fichier en quarantaine correspond à un fichier que l'utilisateur a scanné
            # Note: avshield stocke souvent le chemin complet
            if any(mapping[1] in row["filename"] for mapping in allowed_mappings):
                items.append(dict(row))
                
        conn.close()
        print(f"DEBUG: {len(items)} fichiers en quarantaine trouvés pour {email}")
        return items
    except Exception as e:
        print(f"ERROR: Exception dans get_av_quarantine: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/av/quarantine/restore/{filename}")
async def restore_quarantine_file(filename: str, email: str, destination: str = None):
    """Restaure un fichier de la quarantaine avec validation de propriété"""
    import asyncio
    import os
    
    print(f"DEBUG: Requête Restauration pour {email}: {filename}")
    
    # 1. Valider la propriété
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        # On vérifie si l'utilisateur a déjà scanné ce fichier
        cursor.execute("SELECT id FROM av_scan_mappings WHERE owner_email = %s AND filename LIKE %s", (email, f"%{filename}%"))
        mapping = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not mapping:
            raise HTTPException(status_code=403, detail="Vous n'êtes pas autorisé à restaurer ce fichier.")
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur BD: {err}")

    bin_path = os.path.join(os.path.dirname(__file__), "av-shield", "avshield")
    
    if not os.path.exists(bin_path):
        raise HTTPException(status_code=500, detail="Binaire av-shield introuvable")

    try:
        # Commande: ./avshield quarantine restore <filename> [destination]
        cmd = [bin_path, "quarantine", "restore", filename]
        if destination:
            cmd.append(destination)
            
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=os.path.join(os.path.dirname(__file__), "av-shield")
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            return {"success": True, "message": f"Fichier {filename} restauré.", "output": stdout.decode()}
        else:
            return {"success": False, "message": "Échec de la restauration.", "error": stderr.decode()}
    except Exception as e:
        print(f"ERROR: Exception dans restore_quarantine_file: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/av/quarantine/delete/{filename}")
async def delete_quarantine_file(filename: str, email: str):
    """Supprime définitivement un fichier de la quarantaine avec validation de propriété"""
    import traceback
    base_dir = os.path.dirname(os.path.abspath(__file__))
    av_shield_dir = os.path.join(base_dir, "av-shield")
    av_bin = os.path.join(av_shield_dir, "avshield")

    print(f"DEBUG: Suppression de {filename} par {email}")
    
    # 1. Valider la propriété
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM av_scan_mappings WHERE owner_email = %s AND filename LIKE %s", (email, f"%{filename}%"))
        mapping = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not mapping:
            raise HTTPException(status_code=403, detail="Vous n'êtes pas autorisé à supprimer ce fichier.")
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur BD: {err}")
    try:
        process = subprocess.run([av_bin, "quarantine", "delete", filename], capture_output=True, text=True, cwd=av_shield_dir)
        if process.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Erreur binaire: {process.stderr}")
        return {"success": True, "output": process.stdout}
    except Exception as e:
        print(f"ERROR: Exception dans delete_quarantine_file: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# --- Route Auth ---

@app.get("/auth/check")
async def check_auth_endpoint():
    """Vérifie si un utilisateur principal est configuré."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM mainuser")
        count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return {"configured": count > 0}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur BD: {err}")

@app.post("/auth/request-signup-code")
async def request_signup_code(request: SignupCodeRequest):
    """Génère et envoie un code de vérification pour l'inscription."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM mainuser WHERE email = %s", (request.email,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return {"success": False, "message": "Cet email est déjà utilisé."}
        cursor.close()
        conn.close()
        
        # Add to banned check? Assuming not needed for now unless specifically bounded
        # ... generate code ...
        code = "".join(random.choices(string.digits, k=6))
        signup_codes[request.email] = {
            "code": code,
            "expires": time.time() + 900 # 15 min
        }
        
        success = send_signup_code_email(request.email, request.fullname, code)
        if success:
            return {"success": True, "message": "Un code de vérification a été envoyé à votre adresse email."}
        else:
            return {"success": False, "message": "Erreur lors de l'envoi de l'email."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/signup")
async def signup_endpoint(request: SignupRequest):
    """Vérifie le code et enregistre l'utilisateur."""
    # Validate code
    code_data = signup_codes.get(request.email)
    if not code_data or code_data["code"] != request.code or time.time() > code_data["expires"]:
        return {"success": False, "message": "Code invalide ou expiré."}

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Vérifier si un user existe déjà pour déterminer le rôle de superadmin
        cursor.execute("SELECT COUNT(*) FROM mainuser")
        is_first_user = cursor.fetchone()[0] == 0

        hashed_pw = hash_password(request.password)
        # ONLY first user becomes superadmin now (no request option)
        final_is_superadmin = True if is_first_user else False
        
        query = "INSERT INTO mainuser (fullname, email, telephone, password, is_superadmin) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(query, (request.fullname, request.email, request.telephone, hashed_pw, final_is_superadmin))
        conn.commit()
        cursor.close()
        conn.close()
        
        # Cleanup
        if request.email in signup_codes:
            del signup_codes[request.email]
            
        return {"success": True, "message": "Utilisateur créé avec succès."}
    except mysql.connector.Error as err:
        return {"success": False, "message": "L'email est potentiellement déjà utilisé ou une erreur est survenue."}

        raise HTTPException(status_code=500, detail=f"Erreur BD: {err}")

@app.post("/auth/login")
async def login_endpoint(request: LoginRequest):
    """Vérifie les identifiants de l'utilisateur."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM mainuser WHERE email = %s"
        cursor.execute(query, (request.email,))
        user = cursor.fetchone()
        
        if user:
            cursor.execute("SELECT reason FROM banned_users WHERE email = %s", (request.email,))
            banned = cursor.fetchone()
            if banned:
                cursor.close()
                conn.close()
                return {"success": False, "message": "Votre compte a été banni."}
                
        cursor.close()
        conn.close()

        if user and verify_password(request.password, user["password"]):
            # Ne pas renvoyer le mot de passe haché
            user.pop("password")
            return {"success": True, "message": "Connexion réussie.", "user": user}
        else:
            return {"success": False, "message": "Email ou mot de passe incorrect."}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur BD: {err}")

@app.post("/auth/update-password")
async def update_password_endpoint(request: UpdatePasswordRequest):
    """Met à jour le mot de passe de l'utilisateur après validation de l'ancien."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # Récupérer l'utilisateur
        query = "SELECT * FROM mainuser WHERE email = %s"
        cursor.execute(query, (request.email,))
        user = cursor.fetchone()
        
        if not user or not verify_password(request.old_password, user["password"]):
            cursor.close()
            conn.close()
            return {"success": False, "message": "Ancien mot de passe incorrect."}

        # Mettre à jour le mot de passe
        new_hashed_pw = hash_password(request.new_password)
        update_query = "UPDATE mainuser SET password = %s WHERE email = %s"
        cursor.execute(update_query, (new_hashed_pw, request.email))
        conn.commit()
        
        cursor.close()
        conn.close()
        return {"success": True, "message": "Mot de passe mis à jour avec succès."}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur BD: {err}")

@app.post("/auth/update-profile")
async def update_profile_endpoint(request: UpdateProfileRequest):
    """Met à jour les informations personnelles de l'utilisateur."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        query = "UPDATE mainuser SET fullname = %s, telephone = %s WHERE email = %s"
        cursor.execute(query, (request.fullname, request.telephone, request.email))
        conn.commit()
        
        # Récupérer l'utilisateur mis à jour
        cursor.execute("SELECT id, fullname, email, telephone, is_superadmin FROM mainuser WHERE email = %s", (request.email,))
        user = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé.")
            
        return {"success": True, "message": "Profil mis à jour avec succès.", "user": user}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur BD: {err}")

@app.post("/auth/forgot-password")
async def forgot_password_endpoint(request: ForgotPasswordRequest):
    """Génère un code de réinitialisation et l'envoie par email."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT fullname FROM mainuser WHERE email = %s", (request.email,))
        user = cursor.fetchone()
        
        if not user:
            # Sécurité: Ne pas confirmer si l'email existe ou pas bruyamment
            return {"success": True, "message": "Si l'adresse existe, un code a été envoyé."}
            
        # Générer code 6 chiffres
        code = f"{random.randint(100000, 999999)}"
        reset_codes[request.email] = {"code": code, "expires": time.time() + 600} # 10 mins
        
        from mail import send_reset_code_email
        if send_reset_code_email(request.email, user['fullname'], code):
            return {"success": True, "message": "Code envoyé avec succès."}
        else:
            raise HTTPException(status_code=500, detail="Erreur lors de l'envoi de l'email.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.post("/auth/reset-password")
async def reset_password_endpoint(request: ResetPasswordRequest):
    """Réinitialise le mot de passe si le code est valide."""
    if request.email not in reset_codes:
        raise HTTPException(status_code=400, detail="Aucun code demandé pour cet email.")
    
    data = reset_codes[request.email]
    if time.time() > data['expires']:
        del reset_codes[request.email]
        raise HTTPException(status_code=400, detail="Code expiré.")
    
    if data['code'] != request.code:
        raise HTTPException(status_code=400, detail="Code invalide.")
        
    # Code valide -> reset pwd
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        hashed_pw = hash_password(request.new_password)
        cursor.execute("UPDATE mainuser SET password = %s WHERE email = %s", (hashed_pw, request.email))
        conn.commit()
        
        del reset_codes[request.email]
        return {"success": True, "message": "Mot de passe réinitialisé avec succès."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

# --- Routes Vault (Fichiers) ---

@app.post("/vault/encrypt")
async def vault_encrypt_endpoint(email: str = Query(...), file: UploadFile = File(...)):
    """
    Upload un fichier, le chiffre et le stocke.
    Enregistre les métadonnées dans MySQL.
    """
    try:
        content = await file.read()
        key, nonce, ciphertext = vault_encrypt_file(content)
        
        file_id = str(uuid.uuid4())
        file_path = STORAGE_DIR / file_id
        
        with open(file_path, "wb") as f:
            f.write(nonce + ciphertext)
            
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        query = "INSERT INTO vault_files (file_id, filename, encryption_key, owner_email) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (file_id, file.filename, key.hex(), email))
        conn.commit()
        cursor.close()
        conn.close()

        return {
            "file_id": file_id,
            "filename": file.filename,
            "message": "Fichier sécurisé avec succès."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors du chiffrement : {str(e)}")

@app.get("/vault/list/{email}")
async def vault_list_endpoint(email: str):
    """
    Récupère la liste des fichiers chiffrés pour un utilisateur donné.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        query = "SELECT file_id, filename, created_at FROM vault_files WHERE owner_email = %s ORDER BY created_at DESC"
        cursor.execute(query, (email,))
        files = cursor.fetchall()
        cursor.close()
        conn.close()
        return files
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de la récupération : {str(e)}")

@app.get("/vault/decrypt/{file_id}")
async def vault_decrypt_endpoint(file_id: str, email: str = Query(...)):
    """
    Récupère un fichier chiffré, cherche la clé en base, le déchiffre et le renvoie.
    Vérifie également que l'utilisateur est le propriétaire.
    """
    file_path = STORAGE_DIR / file_id
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Fichier physique introuvable")
        
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        query = "SELECT encryption_key, filename FROM vault_files WHERE file_id = %s AND owner_email = %s"
        cursor.execute(query, (file_id, email))
        record = cursor.fetchone()
        cursor.close()
        conn.close()

        if not record:
            raise HTTPException(status_code=404, detail="Métadonnées du fichier introuvables")

        key = bytes.fromhex(record["encryption_key"])
        original_filename = record["filename"]

        with open(file_path, "rb") as f:
            data = f.read()
            
        if len(data) < 12:
            raise ValueError("Données corrompues")
            
        nonce, ciphertext = data[:12], data[12:]
        decrypted_content = vault_decrypt_file(key, nonce, ciphertext)
        
        return StreamingResponse(
            io.BytesIO(decrypted_content),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={original_filename}"}
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erreur lors du déchiffrement : {str(e)}")

@app.delete("/vault/delete/{file_id}")
async def vault_delete_endpoint(file_id: str, email: str = Query(...)):
    """
    Supprime un fichier du coffre (DB et disque).
    Vérifie également que l'utilisateur est le propriétaire.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        query = "DELETE FROM vault_files WHERE file_id = %s AND owner_email = %s"
        cursor.execute(query, (file_id, email))
        conn.commit()
        
        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Fichier introuvable ou accès refusé")
        cursor.close()
        conn.close()

        file_path = STORAGE_DIR / file_id
        if file_path.exists():
            file_path.unlink()

        return {"success": True, "message": "Fichier supprimé du coffre."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/settings/{email}", response_model=UserSettings)
async def get_settings(email: str):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM user_settings WHERE email = %s", (email,))
        row = cursor.fetchone()
        
        if not row:
            # Return default settings if not found
            return UserSettings(email=email)
            
        cursor.close()
        conn.close()
        return UserSettings(**row)
    except Exception as e:
        print(f"DEBUG: Error in get_settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/settings")
async def save_settings(settings: UserSettings):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Check if settings already exist
        cursor.execute("SELECT email FROM user_settings WHERE email = %s", (settings.email,))
        exists = cursor.fetchone()
        
        if exists:
            query = """
                UPDATE user_settings 
                SET random_password_enabled = %s, 
                    encrypted_result_visible = %s, 
                    scan_history_cleanup_mode = %s, 
                    use_custom_restore_path = %s, 
                    custom_restore_path = %s,
                    is_ai_analysis_enabled = %s,
                    is_realtime_analysis_enabled = %s,
                    require_password_for_delete = %s,
                    require_password_for_download = %s
                WHERE email = %s
            """
            cursor.execute(query, (
                settings.random_password_enabled,
                settings.encrypted_result_visible,
                settings.scan_history_cleanup_mode,
                settings.use_custom_restore_path,
                settings.custom_restore_path,
                settings.is_ai_analysis_enabled,
                settings.is_realtime_analysis_enabled,
                settings.require_password_for_delete,
                settings.require_password_for_download,
                settings.email
            ))
        else:
            query = """
                INSERT INTO user_settings 
                (email, random_password_enabled, encrypted_result_visible, 
                 scan_history_cleanup_mode, use_custom_restore_path, custom_restore_path,
                 is_ai_analysis_enabled, is_realtime_analysis_enabled,
                 require_password_for_delete, require_password_for_download)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (
                settings.email,
                settings.random_password_enabled,
                settings.encrypted_result_visible,
                settings.scan_history_cleanup_mode,
                settings.use_custom_restore_path,
                settings.custom_restore_path,
                settings.is_ai_analysis_enabled,
                settings.is_realtime_analysis_enabled,
                settings.require_password_for_delete,
                settings.require_password_for_download
            ))
            
        conn.commit()
        cursor.close()
        conn.close()
        return {"success": True, "message": "Settings saved successfully"}
    except Exception as e:
        print(f"DEBUG: Error in save_settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/realtime-events")
async def get_realtime_events():
    """
    Récupère l'état du moniteur et la liste des derniers événements.
    """
    from datetime import datetime
    
    global monitor_process
    base_dir = os.path.dirname(os.path.abspath(__file__))
    events_file = os.path.join(base_dir, "database", "realtime_events.json")
    
    events = []
    if os.path.exists(events_file):
        try:
            with open(events_file, "r") as f:
                events = json.load(f)
        except Exception as e:
            print(f"Error reading events file: {e}")

    # Calcul des événements d'aujourd'hui
    today = datetime.now().strftime("%Y-%m-%d")
    today_count = len([e for e in events if e.get('timestamp', '').startswith(today)])
    
    return {
        "status": "ACTIVE" if monitor_process and monitor_process.poll() is None else "INACTIVE",
        "watched_directories": ["/tmp", "Downloads", "Desktop"],
        "events": events,
        "today_count": today_count
    }

@app.get("/admin/all-data")
async def get_all_admin_data(email: str):
    """
    Récupère TOUTES les données de la base pour la vue administrateur.
    Vérifie si le demandeur est bien superadmin.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # 1. Vérifier si le demandeur est superadmin
        cursor.execute("SELECT is_superadmin FROM mainuser WHERE email = %s", (email,))
        requester = cursor.fetchone()
        
        if not requester or not requester["is_superadmin"]:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs.")

        # 2. Récupérer toutes les données
        # Utilisateurs
        cursor.execute("SELECT id, fullname, email, telephone, is_superadmin FROM mainuser")
        users = cursor.fetchall()
        
        # Membres
        cursor.execute("SELECT * FROM members")
        members = cursor.fetchall()
        
        # Mots de passe
        cursor.execute("SELECT * FROM passwords")
        passwords = cursor.fetchall()
        
        # Paramètres
        cursor.execute("SELECT * FROM user_settings")
        settings = cursor.fetchall()
        
        # Coffre-fort (Fichiers)
        cursor.execute("SELECT * FROM vault_files")
        vault_files = cursor.fetchall()
        
        # Utilisateurs bannis
        cursor.execute("SELECT email, reason, banned_at FROM banned_users")
        banned_users = cursor.fetchall()
        
        # Historique Antivirus (données croisées SQLite + MySQL)
        av_history = []
        try:
            import sqlite3
            av_db_path = os.path.join(os.path.dirname(__file__), "av-shield", "database", "avshield.db")
            if os.path.exists(av_db_path):
                # Récupérer les mappings owner_email depuis MySQL
                cursor.execute("SELECT scan_id, owner_email FROM av_scan_mappings")
                mappings = {row["scan_id"]: row["owner_email"] for row in cursor.fetchall()}
                
                # Récupérer les scans depuis SQLite
                conn_sq = sqlite3.connect(av_db_path)
                conn_sq.row_factory = sqlite3.Row
                cursor_sq = conn_sq.cursor()
                cursor_sq.execute("SELECT * FROM scans ORDER BY scan_date DESC")
                for row in cursor_sq.fetchall():
                    row_dict = dict(row)
                    scan_id = row_dict.get("scan_id", "")
                    row_dict["owner_email"] = mappings.get(scan_id, "inconnu")
                    row_dict["result"] = "CLEAN" if row_dict.get("malware_files", 0) == 0 and row_dict.get("suspicious_files", 0) == 0 else "MALWARE"
                    row_dict["critical_count"] = row_dict.get("malware_files", 0)
                    row_dict["high_count"] = row_dict.get("suspicious_files", 0)
                    row_dict["medium_count"] = 0
                    row_dict["low_count"] = row_dict.get("clean_files", 0)
                    av_history.append(row_dict)
                conn_sq.close()
        except Exception as av_err:
            print(f"WARNING: Erreur lors de la récupération de l'historique AV: {av_err}")
        
        cursor.close()
        conn.close()
        
        return {
            "users": users,
            "members": members,
            "passwords": passwords,
            "settings": settings,
            "vault_files": vault_files,
            "banned_users": banned_users,
            "av_history": av_history
        }
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/users/ban")
async def ban_user_endpoint(request: BanRequest):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT is_superadmin FROM mainuser WHERE email = %s", (request.email,))
        requester = cursor.fetchone()
        if not requester or not requester["is_superadmin"]:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs.")
            
        try:
            cursor.execute("INSERT INTO banned_users (email, reason) VALUES (%s, %s)", (request.user_email, request.reason))
            conn.commit()
        except mysql.connector.IntegrityError:
            pass # Already banned
            
        cursor.close()
        conn.close()
        return {"success": True, "message": "Utilisateur banni avec succès."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/users/unban")
async def unban_user_endpoint(request: UnbanRequest):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT is_superadmin FROM mainuser WHERE email = %s", (request.email,))
        requester = cursor.fetchone()
        if not requester or not requester["is_superadmin"]:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs.")
            
        cursor.execute("DELETE FROM banned_users WHERE email = %s", (request.user_email,))
        conn.commit()
        
        cursor.close()
        conn.close()
        return {"success": True, "message": "Utilisateur débanni avec succès."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/send-email")
async def admin_send_email(request: AdminEmailRequest):
    """Envoie un email personnalisé à un utilisateur depuis l'admin."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT is_superadmin FROM mainuser WHERE email = %s", (request.email,))
        requester = cursor.fetchone()
        if not requester or not requester["is_superadmin"]:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs.")
        
        cursor.close()
        conn.close()
        
        success = send_admin_email(request.to_email, request.subject, request.body)
        if success:
            return {"success": True, "message": f"Email envoyé avec succès à {request.to_email}"}
        else:
            return {"success": False, "message": "Erreur lors de l'envoi de l'email."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root():
    return {"message": "Bienvenue sur Crypton API. Allez sur /docs pour tester."}

@app.post("/api/av/explain")
async def explain_detection(req: AIExplainRequest):
    """
    Explique une détection via l'IA (Groq/Llama).
    """
    explanation = analyze_threat(
        req.filename, 
        req.result, 
        req.threat_name, 
        req.heuristic_score, 
        req.entropy
    )
    return {"explanation": explanation}

if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("APP_HOST", "0.0.0.0")
    port = int(os.environ.get("APP_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
