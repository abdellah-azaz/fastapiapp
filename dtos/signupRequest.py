from pydantic import BaseModel

class SignupRequest(BaseModel):
    fullname: str
    email: str
    telephone: str | None = None
    password: str
    code: str
