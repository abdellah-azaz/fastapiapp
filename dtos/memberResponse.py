from pydantic import BaseModel

class MemberResponse(BaseModel):
    id: int
    fullname: str
    mail: str
    message: str | None = None

