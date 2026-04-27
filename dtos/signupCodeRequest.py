from pydantic import BaseModel

class SignupCodeRequest(BaseModel):
    fullname: str
    email: str
