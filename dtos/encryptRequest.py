from pydantic import BaseModel

# --- Modèles de données ---
class EncryptRequest(BaseModel):
    text: str
    owner_email: str

