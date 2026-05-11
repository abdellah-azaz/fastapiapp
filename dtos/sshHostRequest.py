from pydantic import BaseModel

class SSHHostRequest(BaseModel):
    name: str
    host: str
    port: int = 22
    username: str
    password: str = None # Le mot de passe peut être optionnel si on veut juste éditer le nom
    owner_email: str
