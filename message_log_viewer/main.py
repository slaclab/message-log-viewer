import argparse
import logging
import sys

from qtpy.QtWidgets import QApplication
from .message_log_viewer import MessageLogViewer

def main():
    """ Entry point for the application. """
    parser = argparse.ArgumentParser(description="Message Log Viewer")
    parser.add_argument("-a", "--accelerator", default="ALL", help="Accelerator logs to monitor: LCLS, FACET, TESTFAC, ALL")
    parser.add_argument("-l", "--log", default="warning", help="Logging level: debug, info, warning, error, critical")
    app_args = parser.parse_args()

    logging.basicConfig(level=app_args.log.upper())

    app = QApplication(sys.argv)

    message_viewer = MessageLogViewer(app_args.accelerator.upper())
    message_viewer.setWindowTitle('Message Log Viewer')
    message_viewer.resize(1800, 800)
    message_viewer.show()

    exit_code = app.exec()
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
