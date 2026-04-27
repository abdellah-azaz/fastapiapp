from pydantic import BaseModel

class UpdateProfileRequest(BaseModel):
    email: str
    fullname: str
    telephone: str | None = None
