from pydantic import BaseModel
from typing import List, Optional, Literal

class AnalyzeRequest(BaseModel):
    phone: Optional[str] = None
    url: Optional[str] = None
    sms: Optional[str] = None
    file: Optional[str] = None
    mode: Literal["heuristic", "ml", "balanced", "hybrid"] = "balanced"

class AnalyzeResponse(BaseModel):
    label: Literal["scam", "likely_scam", "suspicious", "benign"]
    confidence: float
    explain: List[str]
    used_methods: List[str]

class HealthResponse(BaseModel):
    status: str
    database: str
    model_loaded: bool
