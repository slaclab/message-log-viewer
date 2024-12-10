from dataclasses import dataclass
from datetime import datetime

@dataclass
class LogData:
    time: datetime
    accelerator: str
    origin: str
    user: str
    facility: str
    severity: str
    text: str
