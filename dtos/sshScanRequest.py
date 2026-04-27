from pydantic import BaseModel

class SSHScanRequest(BaseModel):
    host: str
    port: int = 22
    username: str
    password: str
    scan_path: str = "/home"
