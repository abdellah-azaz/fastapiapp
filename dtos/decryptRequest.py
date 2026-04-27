
from pydantic import BaseModel

class DecryptRequest(BaseModel):
    blob: str
    owner_email: str

