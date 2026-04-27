from pydantic import BaseModel


class MemberRequest(BaseModel):
    fullname: str
    mail: str
    owner_email: str

