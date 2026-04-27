from pydantic import BaseModel

class ResetPasswordRequest(BaseModel):
    email: str
    code: str
    new_password: str
