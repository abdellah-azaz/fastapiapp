
from pydantic import BaseModel

class SendPasswordRequest(BaseModel):
    password: str
    member_ids: list[int]

