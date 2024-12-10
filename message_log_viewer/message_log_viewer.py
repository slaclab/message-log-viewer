import json
import logging
import os
import re
import time
from datetime import datetime
from qtpy.QtCore import QDateTime, QEvent, QRegExp, Qt, Signal, QThread, QUrl
from qtpy.QtGui import QIntValidator
from qtpy.QtWebSockets import QWebSocket
from qtpy.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDateTimeEdit, QLabel, QTableView, QFormLayout,
                            QHBoxLayout, QVBoxLayout, QWidget, QPushButton, QHeaderView, QLineEdit, QSpacerItem,
                            QSizePolicy, QMessageBox)
from urllib.parse import quote
from .log_data import LogData
from .log_fetcher import LogFetcher
from .table_models import LokiTableModel, LogViewerProxyModel


class LokiLogViewer(QWidget):
    MATCH_TEXT = "Like"
    NOT_MATCH_TEXT = "Not Like"

    log_received = Signal(LogData)
    error_occurred = Signal(str)

    def __init__(self):
        super().__init__()
        self.connected = False
        self.websocket = QWebSocket()
        self.websocket.textMessageReceived.connect(self.on_message)
        self.websocket.error.connect(self.on_error)
        self.loki_api_url = os.environ.get("LOKI_ADDR", "http://localhost:8080")
        self.setup_logger()
        self.init_ui()
        self.log_received.connect(self.append_new_log_message)

    def setup_logger(self):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def init_ui(self):
        self.resize(1200, 600)
        self.layout = QVBoxLayout()

        self.setup_fiter_controls()
        self.setup_date_controls()
        self.setup_table_ui()
        self.setup_bottom_controls()

        self.setLayout(self.layout)


    def setup_fiter_controls(self):
        self.filter_text = QLineEdit()
        self.filter_text.setPlaceholderText("Enter a keyword to filter results")
        self.filter_text.setMaximumSize(415, 30)
        self.filter_button = QPushButton("Filter")
        self.filter_button.setMaximumSize(120, 30)
        self.filter_button.pressed.connect(self.filter_table)
        self.filter_active_label = QLabel("Filter Active: ")
        self.filter_active_label.setStyleSheet("background-color: orange")
        self.filter_active_label.hide()
        self.first_filter = True

        self.accelerator_dropdown_label = QLabel("Accelerator:")
        self.accelerator_match_dropdown = QComboBox()
        self.accelerator_match_dropdown.addItem("==")
        self.accelerator_match_dropdown.addItem("!=")
        self.accelerator_dropdown = QComboBox()
        self.accelerator_dropdown.addItem("LCLS")
        self.accelerator_dropdown.addItem("FACET")
        self.accelerator_dropdown.addItem("TESTFAC")
        self.accelerator_dropdown.addItem("ALL")

        self.origin_label = QLabel("Origin:")
        self.origin_dropdown = QComboBox()
        self.origin_dropdown.addItem(self.MATCH_TEXT)
        self.origin_dropdown.addItem(self.NOT_MATCH_TEXT)
        self.origin_field = QLineEdit()

        self.user_label = QLabel("User:")
        self.user_dropdown = QComboBox()
        self.user_dropdown.addItem(self.MATCH_TEXT)
        self.user_dropdown.addItem(self.NOT_MATCH_TEXT)
        self.user_field = QLineEdit()

        self.facility_label = QLabel("Facility:")
        self.facility_dropdown = QComboBox()
        self.facility_dropdown.addItem(self.MATCH_TEXT)
        self.facility_dropdown.addItem(self.NOT_MATCH_TEXT)
        self.facility_field = QLineEdit()

        self.severity_label = QLabel("Severity:")
        self.severity_dropdown = QComboBox()
        self.severity_dropdown.addItem(self.MATCH_TEXT)
        self.severity_dropdown.addItem(self.NOT_MATCH_TEXT)
        self.severity_field = QLineEdit()

        self.text_label = QLabel("Text:")
        self.text_dropdown = QComboBox()
        self.text_dropdown.addItem(self.MATCH_TEXT)
        self.text_dropdown.addItem(self.NOT_MATCH_TEXT)
        self.text_field = QLineEdit()

        self.dropdown_layout = QHBoxLayout()
        self.dropdown_layout.addWidget(self.accelerator_dropdown_label)
        self.dropdown_layout.addWidget(self.accelerator_match_dropdown)
        self.dropdown_layout.addWidget(self.accelerator_dropdown)
        self.dropdown_layout.addWidget(self.origin_label)
        self.dropdown_layout.addWidget(self.origin_dropdown)
        self.dropdown_layout.addWidget(self.origin_field)
        self.dropdown_layout.addWidget(self.user_label)
        self.dropdown_layout.addWidget(self.user_dropdown)
        self.dropdown_layout.addWidget(self.user_field)
        self.dropdown_layout.addWidget(self.facility_label)
        self.dropdown_layout.addWidget(self.facility_dropdown)
        self.dropdown_layout.addWidget(self.facility_field)
        self.dropdown_layout.addWidget(self.severity_label)
        self.dropdown_layout.addWidget(self.severity_dropdown)
        self.dropdown_layout.addWidget(self.severity_field)
        self.dropdown_layout.addWidget(self.text_label)
        self.dropdown_layout.addWidget(self.text_dropdown)
        self.dropdown_layout.addWidget(self.text_field)
        self.dropdown_layout.setAlignment(Qt.AlignLeft)

        self.layout.addLayout(self.dropdown_layout)

    def setup_date_controls(self):
        self.date_checkbox = QCheckBox("Use Date Range")
        self.start_date_label = QLabel("Start Date:")
        start_date = QDateTime.currentDateTime().addSecs(-600)
        start_date = start_date.addSecs(-start_date.time().second())
        start_date = start_date.addMSecs(-start_date.time().msec())
        self.start_date = QDateTimeEdit(start_date, calendarPopup=True)
        self.end_date_label = QLabel("End Date:")
        end_date = QDateTime.currentDateTime()
        end_date = end_date.addSecs(-end_date.time().second())
        end_date = end_date.addMSecs(-end_date.time().msec())
        self.end_date = QDateTimeEdit(end_date, calendarPopup=True)

        self.presets = None
        with open("presets.json", "r") as f:
            self.presets = json.load(f)

        self.preset_queries_dropdown = QComboBox()
        self.preset_queries_dropdown.addItem("Select a preset...")
        for preset_name, filters in self.presets.items():
            self.preset_queries_dropdown.addItem(preset_name, userData=filters)
        self.preset_queries_dropdown.currentIndexChanged.connect(self.apply_preset)

        self.line_edits = {
            "Origin": self.origin_field,
            "User": self.user_field,
            "Facility": self.facility_field,
            "Severity": self.severity_field,
            "Text": self.text_field,
        }
        for line_edit in self.line_edits.values():
            line_edit.textChanged.connect(self.reset_combo_box)

        self.calendar_layout = QHBoxLayout()
        self.calendar_layout.setAlignment(Qt.AlignLeft)
        self.calendar_layout.addWidget(self.date_checkbox)
        self.calendar_layout.addWidget(self.start_date_label)
        self.calendar_layout.addWidget(self.start_date)
        self.calendar_layout.addWidget(self.end_date_label)
        self.calendar_layout.addWidget(self.end_date)
        self.calendar_layout.addWidget(self.preset_queries_dropdown)
        self.calendar_layout.addWidget(self.filter_button)

        self.layout.addLayout(self.calendar_layout)
        self.layout.addWidget(self.filter_active_label)

    def setup_table_ui(self):
        self.tableModel = LokiTableModel()
        self.tableView = QTableView(self)

        self.tableProxyModel = LogViewerProxyModel()
        self.tableProxyModel.setFilterKeyColumn(-1)
        self.tableProxyModel.setSourceModel(self.tableModel)

        self.tableView.setModel(self.tableModel)


        initial_column_widths = [200, 100, 200, 100, 200, 100, 230]
        self.tableView.setProperty("showDropIndicator", False)
        self.tableView.setDragDropOverwriteMode(False)
        self.tableView.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tableView.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableView.setCornerButtonEnabled(False)
        self.tableView.setSortingEnabled(True)
        self.tableView.verticalHeader().setVisible(False)
        self.tableView.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for i in range(7):
            self.tableView.horizontalHeader().resizeSection(i, initial_column_widths[i])
        self.tableView.horizontalHeader().setStretchLastSection(True)
        self.tableView.horizontalHeader().setSectionsMovable(True)

        self.layout.addWidget(self.tableView)


    def setup_bottom_controls(self):
        self.bottom_layout = QHBoxLayout()
        self.max_rows_layout = QFormLayout()
        self.max_rows_layout.setContentsMargins(0, 0, 0, 0)
        self.max_rows_layout.setSpacing(0)
        self.action_layout = QHBoxLayout()
        self.max_rows_label = QLabel("Max Rows:")
        self.max_rows_edit = QLineEdit()
        self.max_rows_edit.setValidator(QIntValidator())
        self.max_rows_edit.setText("10000")
        self.max_rows_edit.editingFinished.connect(self.update_max_rows)
        self.max_rows_edit.setMaximumWidth(250)
        self.clear_button = QPushButton("Clear table", self)
        self.clear_button.setMinimumWidth(250)
        self.clear_button.clicked.connect(self.clear_table)
        self.connect_button = QPushButton("Connect to live data", self)
        self.connect_button.setMinimumWidth(250)
        self.connect_button.clicked.connect(self.toggle_connection)
        self.search_button = QPushButton("Retrieve old messages", self)
        self.search_button.setMinimumWidth(250)
        self.search_button.clicked.connect(self.search_messages)
        self.max_rows_layout.addRow(self.max_rows_label, self.max_rows_edit)

        self.max_rows_layout.setSpacing(0)
        self.max_rows_layout.setContentsMargins(0, 0, 0, 0)  # Remove any outer margin
        self.max_rows_layout.setAlignment(Qt.AlignLeft)

        self.action_layout.addWidget(self.clear_button)
        self.action_layout.addWidget(self.connect_button)
        self.action_layout.addWidget(self.search_button)
        self.action_layout.setAlignment(Qt.AlignRight)
        self.bottom_layout.addLayout(self.max_rows_layout)
        self.bottom_layout.addItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        self.bottom_layout.addLayout(self.action_layout)
        self.layout.addLayout(self.bottom_layout)

    def toggle_connection(self):
        if not self.connected:
            self.connect_button.setText("Pause live data")
            self.tail_logs()
        else:
            self.connect_button.setText("Connect to live data")
            self.websocket.close()
        self.connected = not self.connected

    def update_max_rows(self):
        max_rows = int(self.max_rows_edit.text())
        self.tableModel.set_max_entries(max_rows)

    def on_message(self, message):
        # print(f'Received: {message}')
        values = json.loads(message)
        # print(f'Received: {values}')
        for stream in values["streams"]:
            # print(f'Sub stream: Time: {datetime.fromtimestamp(int(stream["values"][0][0])/1e9)} Values: {json.loads(stream["values"][0][1])}')
            # data = json.loads(json.loads(stream["values"][0][1])["log"])
            log_time = datetime.fromtimestamp(int(stream["values"][0][0]) / 1e9)
            log_info = json.loads(stream["values"][0][1])
            # print(f'log time was: {log_time}')
            log_data = LogData(log_time, log_info["accelerator"], log_info["origin"], log_info["user"],
                               log_info["facility"], log_info["severity"], log_info["text"])
            self.log_received.emit(log_data)

    def append_new_log_message(self, log_data):
        self.tableModel.append(log_data)

    def clear_table(self):
        self.tableModel.beginResetModel()
        self.tableModel.log_lines.clear()
        self.tableModel.endResetModel()

    def populate_table(self, data):
        log_entries = []
        streams = data.get("data", {}).get("result", [])
        for stream in streams:
            # Each stream can contain multiple log entries in values
            for value in stream.get("values", []):
                # value is a list where the first item is the timestamp and the second is the log message
                log_time = datetime.fromtimestamp(int(value[0]) / 1e9)
                log_info = json.loads(value[1])

                # Extract necessary fields from log_info
                log_data = LogData(
                    time=log_time,
                    accelerator=log_info.get('accelerator', ""),
                    origin=log_info.get("origin", ""),
                    user=log_info.get("user", ""),
                    facility=log_info.get("facility", ""),
                    severity=log_info.get("severity", ""),
                    text=log_info.get("text", "")
                )
                log_entries.append(log_data)

        self.clear_table()
        log_entries.sort(key=lambda x: x.time)
        for log_data in log_entries:
            self.tableModel.append(log_data)

    def filter_table(self) -> None:
        """Filter the table based on the text typed into the filter bar"""
        if self.first_filter:
            # By delaying setting the proxy model until an actual filter request, performance is improved by a lot
            # when first loading data into the table
            self.first_filter = False
            self.tableView.setModel(self.tableProxyModel)

        accelerator = self.accelerator_dropdown.currentText()
        if accelerator == "ALL":
            accelerator = ""
        self.tableProxyModel.match_accelerator = self.accelerator_match_dropdown.currentText() == "=="

        origin = self.origin_field.text()
        self.tableProxyModel.match_origin = self.origin_dropdown.currentText() == self.MATCH_TEXT
        if not origin:
            self.tableProxyModel.match_origin = True

        facility = self.facility_field.text()
        self.tableProxyModel.match_facility = self.facility_dropdown.currentText() == self.MATCH_TEXT
        if not facility:
            self.tableProxyModel.match_facility = True

        severity = self.severity_field.text()
        self.tableProxyModel.match_severity = self.severity_dropdown.currentText() == self.MATCH_TEXT
        if not severity:
            self.tableProxyModel.match_severity = True

        user = self.user_field.text()
        self.tableProxyModel.match_user = self.user_dropdown.currentText() == self.MATCH_TEXT
        if not user:
            self.tableProxyModel.match_user = True

        text = self.text_field.text()
        self.tableProxyModel.match_text = self.text_dropdown.currentText() == self.MATCH_TEXT
        if not text:
            self.tableProxyModel.match_text = True

        self.tableProxyModel.accelerator_regex = QRegExp(accelerator, Qt.CaseInsensitive, QRegExp.RegExp)
        self.tableProxyModel.origin_regex = QRegExp(origin, Qt.CaseInsensitive, QRegExp.RegExp)
        self.tableProxyModel.facility_regex = QRegExp(facility, Qt.CaseInsensitive, QRegExp.RegExp)
        self.tableProxyModel.severity_regex = QRegExp(severity, Qt.CaseInsensitive, QRegExp.RegExp)
        self.tableProxyModel.user_regex = QRegExp(user, Qt.CaseInsensitive, QRegExp.RegExp)
        self.tableProxyModel.text_regex = QRegExp(text, Qt.CaseInsensitive, QRegExp.RegExp)
        self.tableProxyModel.use_date = self.date_checkbox.isChecked()
        self.tableProxyModel.start_date = self.start_date.dateTime()
        self.tableProxyModel.end_date = self.end_date.dateTime()

        self.tableProxyModel.invalidateFilter()

    def apply_preset(self, index):
        if index <= 0:
            # Handle the default selection or reset
            for line_edit in self.line_edits.values():
                line_edit.clear()
            return

        # Get the filter values associated with the selected preset
        filters = self.preset_queries_dropdown.itemData(index)
        if filters:
            for column_name in self.tableModel.column_names:
                if column_name != "Time" and column_name != "Accelerator":
                    value = filters.get(column_name, '')
                    self.line_edits[column_name].setText(value)
        else:
            # Clear all line edits if no filters are present
            for line_edit in self.line_edits.values():
                line_edit.clear()

    def reset_combo_box(self):
        self.preset_queries_dropdown.currentIndexChanged.disconnect()
        self.preset_queries_dropdown.setCurrentIndex(0)  # Reset to default item
        self.preset_queries_dropdown.currentIndexChanged.connect(self.apply_preset)

    def closeEvent(self, event: QEvent):
        if self.connected:
            self.toggle_connection()
        event.accept()

    def on_error(self, error):
        error_message = self.websocket.errorString()
        self.logger.error(f"WebSocket Error: {error_message}")
        QMessageBox.critical(self, "WebSocket Error", error_message)

    def build_query(self):
        # Start with the base query
        query = '{job="accelerator_logs"}'

        # Accelerator filter
        accelerator = self.accelerator_dropdown.currentText()
        if accelerator != "ALL":
            match_operator = "|=" if self.accelerator_match_dropdown.currentText() == "==" else "!="
            query += f' {match_operator} `"accelerator": "{accelerator}"`'

        # Other filters
        filters = [
            ("origin", self.origin_field.text(), self.origin_dropdown.currentText() == self.MATCH_TEXT),
            ("user", self.user_field.text(), self.user_dropdown.currentText() == self.MATCH_TEXT),
            ("facility", self.facility_field.text(), self.facility_dropdown.currentText() == self.MATCH_TEXT),
            ("severity", self.severity_field.text(), self.severity_dropdown.currentText() == self.MATCH_TEXT),
            ("text", self.text_field.text(), self.text_dropdown.currentText() == self.MATCH_TEXT),
        ]

        for key, value, should_match in filters:
            if value:
                operator = "=~" if should_match else "!~"
                escaped_value = re.escape(value)
                # Build the regex pattern
                pattern = f'.*{escaped_value}.*'
                query += f' | json | {key} {operator} "{pattern}"'

        # URL-encode the entire query
        encoded_query = quote(query, safe='')
        return encoded_query

    def search_messages(self):
        query = self.build_query()
        start_date = self.start_date.dateTime()
        end_date = self.end_date.dateTime()
        start_ns = start_date.toMSecsSinceEpoch() * 1000000
        end_ns = end_date.toMSecsSinceEpoch() * 1000000
        url = f"{self.loki_api_url}/loki/api/v1/query_range?query={query}&start={start_ns}&end={end_ns}&limit=1000&direction=backward"
        print(f'fetching data from: {url}')
        self.thread = QThread()
        self.worker = LogFetcher(url)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.fetch_logs)
        self.worker.data_fetched.connect(self.populate_table)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def tail_logs(self):
        query = self.build_query()
        curr_time = int(time.time())
        self.logger.info(
            f"Attempting conneciton to: {self.loki_api_url.replace('http', 'ws')}/loki/api/v1/tail?query={query}&start={curr_time}")
        url = QUrl(f"{self.loki_api_url.replace('http', 'ws')}/loki/api/v1/tail?query={query}&start={curr_time}")
        self.websocket.open(url)
