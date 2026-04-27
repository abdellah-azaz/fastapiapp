from pydantic import BaseModel

class BanRequest(BaseModel):
    user_email: str
    email: str
    reason: str | None = None
