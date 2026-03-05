import os
import base64
import secrets
import string
import mysql.connector
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from contextlib import asynccontextmanager
from mail import send_password_email
from dotenv import load_dotenv

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

# --- Database Management ---
def init_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INT AUTO_INCREMENT PRIMARY KEY,
                psswrd TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS members (
                id INT AUTO_INCREMENT PRIMARY KEY,
                fullname VARCHAR(255) NOT NULL,
                mail VARCHAR(255) NOT NULL
            )
        """)
        conn.commit()
        cursor.close()
        conn.close()
        print("Database initialized successfully.")
    except mysql.connector.Error as err:
        print(f"Error: {err}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize the database
    init_db()
    yield
    # Shutdown logic (if any) can go here

# --- Modèles de données ---
class EncryptRequest(BaseModel):
    text: str

class DecryptRequest(BaseModel):
    blob: str

class CryptoResponse(BaseModel):
    result: str

class MemberRequest(BaseModel):
    fullname: str
    mail: str

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

# --- Application FastAPI ---
app = FastAPI(
    title="Crypton API",
    description="Une API simple pour chiffrer et déchiffrer des messages avec AES-GCM et les stocker en base de données.",
    version="1.1.0",
    lifespan=lifespan
)

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

def save_to_db(encrypted_text: str):
    """Enregistre le mot de passe chiffré dans MySQL."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO passwords (psswrd) VALUES (%s)", (encrypted_text,))
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
    save_to_db(resultat)
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
        query = "INSERT INTO members (fullname, mail) VALUES (%s, %s)"
        cursor.execute(query, (member.fullname, member.mail))
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

@app.get("/members", response_model=MemberListResponse)
async def list_members_endpoint():
    """
    Récupère la liste de tous les membres.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, fullname, mail FROM members")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return MemberListResponse(members=rows, count=len(rows))
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")

@app.get("/members/search", response_model=MemberListResponse)
async def search_members_endpoint(fullname: str):
    """
    Recherche des membres par leur nom complet (partiel).
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        query = "SELECT id, fullname, mail FROM members WHERE fullname LIKE %s"
        cursor.execute(query, (f"%{fullname}%",))
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
        query = "UPDATE members SET fullname = %s, mail = %s WHERE id = %s"
        cursor.execute(query, (member.fullname, member.mail, member_id))
        conn.commit()
        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Membre non trouvé")
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
async def delete_member_endpoint(member_id: int):
    """
    Supprime un membre de la base de données.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM members WHERE id = %s", (member_id,))
        conn.commit()
        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Membre non trouvé")
        cursor.close()
        conn.close()
        return {"message": "Membre supprimé avec succès !"}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Erreur base de données: {err}")

@app.post("/generate", response_model=CryptoResponse)
async def generate_password_endpoint():
    """
    Génère un mot de passe aléatoire, le chiffre et l'enregistre dans la base de données.
    """
    # Génération d'un mot de passe sécurisé (16 caractères)
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(16))
    
    resultat = chiffrer(password)
    save_to_db(resultat)
    
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

@app.get("/")
async def root():
    return {"message": "Bienvenue sur Crypton API. Allez sur /docs pour tester."}

if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("APP_HOST", "127.0.0.1")
    port = int(os.environ.get("APP_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
