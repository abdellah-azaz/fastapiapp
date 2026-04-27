from pydantic import BaseModel

class UpdatePasswordRequest(BaseModel):
    email: str
    old_password: str
    new_password: str
