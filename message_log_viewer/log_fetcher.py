import requests
from qtpy.QtCore import QObject, Signal
from typing import Optional

class LogFetcher(QObject):
    """
    A class for retrieving historical log data given a query url

    Parameters
    ----------
    url : str
        The url of the Loki instance to request data from along with any associated query parameters
        e.g. http://localhost:80/loki/api/v1/query_range?query={query}&start={start_ns}&end={end_ns}
    """
    data_fetched = Signal(dict)
    finished = Signal()

    def __init__(self, url: str, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.url = url

    def fetch_logs(self) -> None:
        """
        Fetch the log data for the given url. When all data has been retrieved from log storage, emits a signal
        letting the client know the data is ready.
        """
        try:
            response = requests.get(self.url)
            response.raise_for_status()
            data = response.json()
            self.data_fetched.emit(data)
        except requests.RequestException as e:
            print(f"Request for log data failed! Request url: {self.url} Error: {e}")
        finally:
            self.finished.emit()
