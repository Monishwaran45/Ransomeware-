import os
import csv
from datetime import datetime
from typing import Dict, Any, Optional

class MonitoringLogger:
    """
    Structured logger writing predictions to logs/predictions.csv and high-risk alerts to logs/alerts.csv.
    """

    def __init__(
        self,
        predictions_csv: str = "logs/predictions.csv",
        alerts_csv: str = "logs/alerts.csv"
    ):
        self.predictions_csv = predictions_csv
        self.alerts_csv = alerts_csv
        self._init_csv_headers()

    def _init_csv_headers(self):
        os.makedirs(os.path.dirname(self.predictions_csv), exist_ok=True)
        os.makedirs(os.path.dirname(self.alerts_csv), exist_ok=True)

        fieldnames = [
            "timestamp", "prediction", "probability", "risk_level",
            "process_context", "feature_source", "monitoring_mode"
        ]

        if not os.path.exists(self.predictions_csv):
            with open(self.predictions_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(fieldnames)

        if not os.path.exists(self.alerts_csv):
            with open(self.alerts_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(fieldnames)

    def log_prediction(
        self,
        prediction_result: Dict[str, Any],
        process_context: str = "System Baseline",
        feature_source: str = "CIC-MalMem Replay",
        monitoring_mode: str = "REPLAY"
    ):
        """Logs prediction entry to predictions.csv, and to alerts.csv if risk is HIGH."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pred_label = prediction_result.get("prediction", "Unknown")
        prob = prediction_result.get("probability", 0.0)
        risk = prediction_result.get("risk_level", "LOW")

        row = [
            timestamp, pred_label, f"{prob:.4f}", risk,
            process_context, feature_source, monitoring_mode
        ]

        # Log to predictions.csv
        with open(self.predictions_csv, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(row)

        # Log to alerts.csv if HIGH risk
        if risk == "HIGH" or pred_label == "Ransomware":
            with open(self.alerts_csv, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(row)
