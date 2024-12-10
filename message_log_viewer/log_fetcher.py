import requests
from qtpy.QtCore import QObject, Signal

class LogFetcher(QObject):
    data_fetched = Signal(dict)
    finished = Signal()

    def __init__(self, url):
        super().__init__()
        self.url = url

    def fetch_logs(self):
        try:
            response = requests.get(self.url)
            response.raise_for_status()
            data = response.json()
            self.data_fetched.emit(data)
        except requests.RequestException as e:
            print(f"HTTP Request failed: {e}")
        finally:
            self.finished.emit()
