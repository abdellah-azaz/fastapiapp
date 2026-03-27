import os
import secrets
import uuid
import shutil
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import io

# --- Configuration ---
STORAGE_DIR = Path("storage/encrypted")
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="Crypton File API",
    description="API pour chiffrer et déchiffrer des fichiers avec AES-GCM.",
    version="2.0.0"
)

# --- Logic ---

def encrypt_file(file_content: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Chiffre le contenu d'un fichier.
    Retourne (key, nonce, ciphertext)
    """
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, file_content, None)
    return key, nonce, ciphertext

def decrypt_file(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Déchiffre le contenu d'un fichier.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# --- Routes ---

@app.post("/encrypt")
async def encrypt_endpoint(file: UploadFile = File(...)):
    """
    Upload un fichier, le chiffre et le stocke.
    Renvoie l'ID du fichier et la clé de déchiffrement (HEX).
    """
    try:
        content = await file.read()
        key, nonce, ciphertext = encrypt_file(content)
        
        file_id = str(uuid.uuid4())
        file_path = STORAGE_DIR / file_id
        
        # On stocke le nonce (12 octets) suivi du ciphertext
        with open(file_path, "wb") as f:
            f.write(nonce + ciphertext)
            
        return {
            "file_id": file_id,
            "key": key.hex(),
            "filename": file.filename,
            "message": "Fichier chiffré et stocké avec succès. GARDER LA CLÉ PRÉCIEUSEMENT."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors du chiffrement : {str(e)}")

@app.get("/decrypt/{file_id}")
async def decrypt_endpoint(file_id: str, key_hex: str = Query(..., alias="key")):
    """
    Récupère un fichier chiffré, le déchiffre à la volée et le renvoie.
    """
    file_path = STORAGE_DIR / file_id
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Fichier introuvable")
        
    try:
        key = bytes.fromhex(key_hex)
        with open(file_path, "rb") as f:
            data = f.read()
            
        if len(data) < 12:
            raise ValueError("Données du fichier corrompues")
            
        nonce, ciphertext = data[:12], data[12:]
        decrypted_content = decrypt_file(key, nonce, ciphertext)
        
        # On renvoie le contenu déchiffré comme un flux
        return StreamingResponse(
            io.BytesIO(decrypted_content),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename=decrypted_{file_id}"}
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erreur lors du déchiffrement : {str(e)}")

@app.get("/")
async def root():
    return {"message": "Bienvenue sur Crypton File API. Utilisez /docs pour tester."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
