import os
import time
import csv
from datetime import datetime
from typing import Dict, Any
from behavior_monitoring.file_monitor import FileMonitor
from behavior_monitoring.process_monitor import BehavioralProcessMonitor

class BehavioralEventAggregator:
    """
    Aggregates file system and process behavior events over configurable time windows.
    Stores events in logs/behavioral_events.csv for behavioral research.
    
    CRITICAL DOCUMENTATION NOTE:
    Behavioral features require a separately trained model unless the training dataset
    contains the exact same behavioral features. Do not feed these features into the
    CIC-MalMem memory model.
    """

    def __init__(
        self,
        watch_path: str = ".",
        window_seconds: int = 5,
        output_csv: str = "logs/behavioral_events.csv"
    ):
        self.window_seconds = window_seconds
        self.output_csv = output_csv
        self.file_monitor = FileMonitor(watch_path=watch_path)
        self.process_monitor = BehavioralProcessMonitor()
        self._init_csv()

    def _init_csv(self):
        os.makedirs(os.path.dirname(self.output_csv), exist_ok=True)
        if not os.path.exists(self.output_csv):
            with open(self.output_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "window_seconds",
                    "files_created", "files_modified", "files_deleted", "files_renamed",
                    "cpu_percent", "ram_percent", "disk_read_bytes", "disk_write_bytes"
                ])

    def run_window(self) -> Dict[str, Any]:
        """Collects metrics accumulated over one time window."""
        stats_files = self.file_monitor.get_window_stats()
        stats_proc = self.process_monitor.get_system_behavior_stats()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        record = {
            "timestamp": timestamp,
            "window_seconds": self.window_seconds,
            **stats_files,
            **stats_proc
        }

        # Log to CSV
        with open(self.output_csv, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                record["timestamp"], record["window_seconds"],
                record["files_created"], record["files_modified"],
                record["files_deleted"], record["files_renamed"],
                record["cpu_percent"], record["ram_percent"],
                record["disk_read_bytes"], record["disk_write_bytes"]
            ])

        return record

    def start_monitoring(self, duration_seconds: int = 15):
        """Starts file observer and collects aggregated windows for specified duration."""
        print(f"[BehavioralMonitor] Starting live monitoring (Window: {self.window_seconds}s, Path: '.')...")
        print("Note: Behavioral metrics are logged separately and NOT fed into the CIC-MalMem model.")
        
        self.file_monitor.start()
        start_time = time.time()

        try:
            while time.time() - start_time < duration_seconds:
                time.sleep(self.window_seconds)
                rec = self.run_window()
                print(
                    f"[{rec['timestamp']}] Files: +{rec['files_created']} ~{rec['files_modified']} "
                    f"-{rec['files_deleted']} move:{rec['files_renamed']} | "
                    f"CPU: {rec['cpu_percent']}% RAM: {rec['ram_percent']}% "
                    f"DiskWrite: {rec['disk_write_bytes']}B"
                )
        finally:
            self.file_monitor.stop()
            print("[BehavioralMonitor] Monitoring stopped cleanly.")
