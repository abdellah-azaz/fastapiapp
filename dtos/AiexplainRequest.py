
from pydantic import BaseModel

class AIExplainRequest(BaseModel):
    filename: str
    result: str
    threat_name: str | None = None
    heuristic_score: int
    entropy: float

