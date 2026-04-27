
from pydantic import BaseModel

class FlutterPasswords(BaseModel):
    password: str
    owner_email: str

