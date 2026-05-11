from pydantic import BaseModel

class AdminCreateUserRequest(BaseModel):
    fullname: str
    email: str
    telephone: str | None = None
    password: str
    is_superadmin: bool = False
