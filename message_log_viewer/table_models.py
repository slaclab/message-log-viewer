from collections import deque
from .log_data import LogData
from typing import Optional
from qtpy.QtCore import QAbstractTableModel, QDateTime, QModelIndex, QObject, QRegExp, QSortFilterProxyModel, Qt
from qtpy.QtGui import QBrush


class MessageLogTableModel(QAbstractTableModel):
    """
    The table model for holding and displaying the log entries received from Loki.

    Parameters
    ----------
    max_entries : int, optional
        The maximum number of rows to display in the table
    parent : QObject, optional
        The parent of this widget
    """
    def __init__(self, max_entries: Optional[int] = 10000, parent: Optional[QObject] = None):
        super().__init__(parent=parent)
        self.log_lines = deque()
        self.max_entries = max_entries
        self.column_names = (
            "Time",
            "Accelerator",
            "Origin",
            "User",
            "Facility",
            "Severity",
            "Text",
        )

    def rowCount(self, parent) -> int:
        """ Return the row count of the table """
        if parent is not None and parent.isValid():
            return 0
        return len(self.log_lines)

    def columnCount(self, parent) -> int:
        """Return the column count of the table"""
        if parent is not None and parent.isValid():
            return 0
        return len(self.column_names)

    def data(self, index: QModelIndex, role: int):
        """ Return the data for the given role """
        if not index.isValid():
            return None

        if role != Qt.DisplayRole and role != Qt.TextColorRole:
            return None

        column_name = self.column_names[index.column()]
        log_data = self.log_lines[index.row()]

        if role == Qt.DisplayRole:
            return self.getData(column_name, log_data)
        elif role == Qt.TextColorRole:
            if column_name == "Severity":
                if self.getData(column_name, log_data) == "MAJOR":
                    return QBrush(Qt.red)
                elif self.getData(column_name, log_data) == "MINOR":
                    return QBrush(Qt.darkYellow)

    def getData(self, column_name: str, log_data: LogData):
        """ Retrieve the data for the given column name from the LogData object """
        if column_name == "Time":
            return str(log_data.time)
        elif column_name == "Accelerator":
            return log_data.accelerator
        elif column_name == "Origin":
            return log_data.origin
        elif column_name == "User":
            return log_data.user
        elif column_name == "Facility":
            return log_data.facility
        elif column_name == "Severity":
            return log_data.severity
        elif column_name == "Text":
            return log_data.text

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        """ Retrieve the header data for the given section """
        if role != Qt.DisplayRole:
            return super().headerData(section, orientation, role)

        return str(self.column_names[section])

    def set_max_entries(self, max_entries: int) -> None:
        """
        Set the maximum number of rows to display for the table. Remove excess lines as needed if there are already
        too many to display
        """
        self.max_entries = max_entries
        if len(self.log_lines) > self.max_entries:
            excess = len(self.log_lines) - self.max_entries
            for _ in range(excess):
                self.beginRemoveRows(QModelIndex(), len(self.log_lines) - 1, len(self.log_lines) - 1)
                self.log_lines.pop()
                self.endRemoveRows()

    def append(self, log_data: LogData) -> None:
        """ Append a new row of log data to the table """
        self.beginInsertRows(QModelIndex(), 0, 0)
        self.log_lines.appendleft(log_data)
        self.endInsertRows()
        if len(self.log_lines) > self.max_entries:
            last_row = len(self.log_lines) - 1
            self.beginRemoveRows(QModelIndex(), last_row, last_row)
            self.log_lines.pop()
            self.endRemoveRows()


class LogViewerProxyModel(QSortFilterProxyModel):
    """
    An implementation of a QSortFilterProxyModel to allow for filtering on all table columns at the same time

    Parameters
    ----------
    parent : QObject
        The parent of this widget
    """

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.accelerator_regex = QRegExp("", Qt.CaseInsensitive, QRegExp.RegExp)
        self.origin_regex = QRegExp("", Qt.CaseInsensitive, QRegExp.RegExp)
        self.user_regex = QRegExp("", Qt.CaseInsensitive, QRegExp.RegExp)
        self.facility_regex = QRegExp("", Qt.CaseInsensitive, QRegExp.RegExp)
        self.severity_regex = QRegExp("", Qt.CaseInsensitive, QRegExp.RegExp)
        self.text_regex = QRegExp("", Qt.CaseInsensitive, QRegExp.RegExp)

        self.start_date = None
        self.end_date = None
        self.use_date = False

        self.match_accelerator = True
        self.match_origin = True
        self.match_user = True
        self.match_facility = True
        self.match_severity = True
        self.match_text = True

    def filterAcceptsRow(self, source_row, source_parent) -> bool:
        """ Based on the filters set by the user, determine whether each row in the table should be displayed or not """
        date_index = self.sourceModel().index(source_row, 0, source_parent)
        date_match = True
        if self.use_date:
            log_date_str = self.sourceModel().data(date_index, Qt.DisplayRole)
            if log_date_str != None:
                log_date_str = log_date_str[:23]
                log_date = QDateTime.fromString(log_date_str, "yyyy-MM-dd HH:mm:ss.zzz")
                if log_date < self.start_date or log_date > self.end_date:
                    date_match = False

        filter_fields = [
            (1, self.accelerator_regex, self.match_accelerator),
            (2, self.origin_regex, self.match_origin),
            (3, self.user_regex, self.match_user),
            (4, self.facility_regex, self.match_facility),
            (5, self.severity_regex, self.match_severity),
            (6, self.text_regex, self.match_text),
        ]

        source_model = self.sourceModel()
        matches = []
        for col_index, regex, should_match in filter_fields:
            index = source_model.index(source_row, col_index, source_parent)
            data = source_model.data(index, Qt.DisplayRole)
            if data != None:
                match_result = regex.indexIn(data) != -1
            else:
                match_result = False

            matches.append(match_result == should_match)

        return all(matches) and date_match
