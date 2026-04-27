from pydantic import BaseModel

class AuthResponse(BaseModel):
    success: bool
    message: str
    user: dict | None = None
