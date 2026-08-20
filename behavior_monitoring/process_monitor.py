import psutil
from typing import Dict, Any

class BehavioralProcessMonitor:
    """
    Monitors process CPU percentage, RAM usage, and Disk I/O statistics across the system.
    """

    def __init__(self):
        # Initialize disk I/O baseline
        self.last_disk_io = psutil.disk_io_counters()

    def get_system_behavior_stats(self) -> Dict[str, Any]:
        """Collects current system resource utilization snapshot."""
        cpu_percent = psutil.cpu_percent(interval=None)
        mem_info = psutil.virtual_memory()

        current_disk_io = psutil.disk_io_counters()
        read_bytes_delta = 0
        write_bytes_delta = 0

        if self.last_disk_io and current_disk_io:
            read_bytes_delta = current_disk_io.read_bytes - self.last_disk_io.read_bytes
            write_bytes_delta = current_disk_io.write_bytes - self.last_disk_io.write_bytes

        self.last_disk_io = current_disk_io

        return {
            "cpu_percent": float(cpu_percent),
            "ram_percent": float(mem_info.percent),
            "disk_read_bytes": int(read_bytes_delta),
            "disk_write_bytes": int(write_bytes_delta)
        }
