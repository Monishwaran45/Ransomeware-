import time
from typing import Dict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileActivityHandler(FileSystemEventHandler):
    """
    Watchdog event handler counting file operations (create, modify, delete, move/rename).
    """

    def __init__(self):
        super().__init__()
        self.reset_counters()

    def reset_counters(self):
        self.created_count = 0
        self.modified_count = 0
        self.deleted_count = 0
        self.moved_count = 0

    def on_created(self, event):
        if not event.is_directory:
            self.created_count += 1

    def on_modified(self, event):
        if not event.is_directory:
            self.modified_count += 1

    def on_deleted(self, event):
        if not event.is_directory:
            self.deleted_count += 1

    def on_moved(self, event):
        if not event.is_directory:
            self.moved_count += 1

    def get_stats_and_reset(self) -> Dict[str, int]:
        stats = {
            "files_created": self.created_count,
            "files_modified": self.modified_count,
            "files_deleted": self.deleted_count,
            "files_renamed": self.moved_count
        }
        self.reset_counters()
        return stats

class FileMonitor:
    """
    File system activity monitoring module using watchdog.
    
    NOTE: Behavioral features require a separately trained model unless the training
    dataset contains the exact same behavioral features.
    """

    def __init__(self, watch_path: str = "."):
        self.watch_path = watch_path
        self.handler = FileActivityHandler()
        self.observer = Observer()
        self.observer.schedule(self.handler, path=self.watch_path, recursive=True)
        self.is_running = False

    def start(self):
        if not self.is_running:
            self.observer.start()
            self.is_running = True

    def stop(self):
        if self.is_running:
            self.observer.stop()
            self.observer.join()
            self.is_running = False

    def get_window_stats(self) -> Dict[str, int]:
        return self.handler.get_stats_and_reset()
