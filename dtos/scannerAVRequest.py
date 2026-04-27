from pydantic import BaseModel

class ScannerAVRequest(BaseModel):
    path: str
    owner_email: str
    auto: bool = False
    report: bool = True
    html: bool = False
