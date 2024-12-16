from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class LogData:
    """
    A single log entry for display in the user interface.

    Parameters
    ----------
    time : datetime
        The timestamp of the log entry
    accelerator : str
        Currently one of LCLS, FACET, TESTFAC
    origin : str
        The IOC or server that generated the log message
    user : str, optional
        The user account that generated the message
    facility : str
        Facility associated with this entry
    severity : str, optional
        The alarm or error severity associated with this message
    text : str
        The text that was logged
    """
    time: datetime
    accelerator: str
    origin: str
    user: Optional[str]
    facility: str
    severity: Optional[str]
    text: str
