from pydantic import BaseModel

class AdminEmailRequest(BaseModel):
    email: str  # admin email (requester)
    to_email: str  # recipient
    subject: str
    body: str
