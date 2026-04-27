from pydantic import BaseModel
from .memberResponse import MemberResponse

class MemberListResponse(BaseModel):
    members: list[MemberResponse]
    count: int

