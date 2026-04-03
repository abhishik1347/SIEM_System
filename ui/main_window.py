import sys
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
    QVBoxLayout,
    QLabel
)
from PySide6.QtGui import QColor
from PySide6.QtCore import QTimer, Qt

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from backend.collector.windows_logs import get_system_logs
from backend.parser.windows_parser import parse_windows_event
from backend.normalizer.ocsf_mapper import to_ocsf
from backend.normalizer.mitre_mapper import map_to_mitre
from backend.scorer.risk_engine import calculate_risk
from backend.aggregator.risk_aggregator import aggregate_by_user
from backend.anomaly.anomaly_engine import detect_anomaly
from backend.database.db_manager import insert_log


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Elite AI-Based SIEM Risk & Anomaly Dashboard")
        self.setGeometry(150, 100, 1350, 820)


        central_widget = QWidget()
        layout = QVBoxLayout()

        self.summary_label = QLabel("Top Risky User: None")
        self.summary_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(self.summary_label)

        self.table = QTableWidget()
        layout.addWidget(self.table)

        self.figure = Figure(figsize=(6, 3))
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        self.load_logs()

        # Auto refresh every 5 seconds
        self.timer = QTimer()
        self.timer.timeout.connect(self.load_logs)
        self.timer.start(5000)

    # ======================================================
    # Main Processing Pipeline
    # ======================================================
    def load_logs(self):

        raw_logs = get_system_logs(300)

        logs = []

        for log in raw_logs:
            parsed = parse_windows_event(log)
            ocsf_event = to_ocsf(parsed)
            risk = calculate_risk(parsed)
            mitre = map_to_mitre(parsed["event_id"])

            parsed["risk"] = risk
            parsed["ocsf"] = ocsf_event
            parsed["mitre"] = mitre

            logs.append(parsed)

        # ================= Aggregate User Risk =================
        user_summary = aggregate_by_user(logs)

        anomaly_users = {}

        for user, total_risk in user_summary.items():
            is_anomaly, z_score, confidence = detect_anomaly(user, total_risk)
            anomaly_users[user] = (is_anomaly, confidence)

        # ================= Update Top Risk Label =================
        if user_summary:
            top_user = max(user_summary, key=user_summary.get)
            top_score = user_summary[top_user]
            self.summary_label.setText(
                f"Top Risky User: {top_user} | Total Risk: {top_score}"
            )
        else:
            self.summary_label.setText("Top Risky User: None")

        # ================= Setup Table =================
        self.table.setRowCount(len(logs))
        self.table.setColumnCount(9)

        self.table.setHorizontalHeaderLabels(
            [
                "Event ID",
                "Time",
                "User",
                "Action",
                "Risk",
                "Category",
                "MITRE",
                "Anomaly",
                "Anomaly Score"
            ]
        )

        # ================= Populate Table + Store DB =================
        for row, log in enumerate(logs):

            user = log["user"]

            if user in anomaly_users:
                is_anomaly, confidence = anomaly_users[user]
                anomaly_status = "YES" if is_anomaly else "NO"
                anomaly_score = confidence
            else:
                anomaly_status = "NO"
                anomaly_score = 0

            # Add anomaly to event before storing
            log["anomaly"] = anomaly_status

            # Store in database
            insert_log(log)

            # Fill table
            self.table.setItem(row, 0, QTableWidgetItem(str(log["event_id"])))
            self.table.setItem(row, 1, QTableWidgetItem(log["time"]))
            self.table.setItem(row, 2, QTableWidgetItem(str(user)))
            self.table.setItem(row, 3, QTableWidgetItem(log["action"]))
            self.table.setItem(row, 4, QTableWidgetItem(str(log["risk"])))
            self.table.setItem(row, 5, QTableWidgetItem(log["ocsf"]["category"]))
            self.table.setItem(row, 6, QTableWidgetItem(log["mitre"]))
            self.table.setItem(row, 7, QTableWidgetItem(anomaly_status))
            self.table.setItem(row, 8, QTableWidgetItem(str(anomaly_score)))

            # Coloring
            if anomaly_status == "YES":
                color = QColor(128, 0, 128)
            elif log["risk"] >= 8:
                color = QColor(255, 0, 0)
            elif log["risk"] >= 5:
                color = QColor(255, 165, 0)
            elif log["risk"] >= 3:
                color = QColor(255, 255, 0)
            else:
                color = QColor(255, 255, 255)

            for col in range(9):
                self.table.item(row, col).setBackground(color)

        self.table.resizeColumnsToContents()
        self.table.sortItems(4, Qt.DescendingOrder)

        self.update_chart(logs)

    # ======================================================
    # Risk Distribution Chart
    # ======================================================
    def update_chart(self, logs):

        self.figure.clear()
        ax = self.figure.add_subplot(111)

        risks = [log["risk"] for log in logs]

        ax.hist(risks, bins=10)
        ax.set_title("Risk Distribution")
        ax.set_xlabel("Risk Score")
        ax.set_ylabel("Frequency")

        self.canvas.draw()


# ======================================================
# Run Application
# ======================================================
app = QApplication(sys.argv)

window = MainWindow()
window.show()

sys.exit(app.exec())
