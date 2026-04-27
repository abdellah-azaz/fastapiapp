
from pydantic import BaseModel

class PasswordGenerateRequest(BaseModel):
    owner_email: str

