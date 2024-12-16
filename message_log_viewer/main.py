import sys

from qtpy.QtWidgets import QApplication
from .message_log_viewer import LokiLogViewer

def main():
    app = QApplication(sys.argv)

    message_viewer = LokiLogViewer()
    message_viewer.setWindowTitle('Message Log Viewer')
    message_viewer.resize(1800, 800)
    message_viewer.show()

    exit_code = app.exec()
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
