from pydantic import BaseModel

class UnbanRequest(BaseModel):
    user_email: str
    email: str
