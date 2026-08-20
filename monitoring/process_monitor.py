import psutil
from typing import List, Dict, Any

class ProcessMonitor:
    """
    Safely enumerates running processes and collects process/system level metrics.
    """

    def enumerate_processes(self) -> List[Dict[str, Any]]:
        """Returns snapshot list of running processes with basic metadata."""
        processes = []
        for p in psutil.process_iter(['pid', 'name', 'num_threads', 'num_handles', 'memory_info']):
            try:
                info = p.info
                processes.append({
                    "pid": info['pid'],
                    "name": info['name'] or "Unknown",
                    "num_threads": info['num_threads'] or 0,
                    "num_handles": info['num_handles'] or 0,
                    "rss_memory": info['memory_info'].rss if info['memory_info'] else 0
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return processes

    def get_system_process_summary(self) -> Dict[str, Any]:
        """Calculates aggregated process metrics across all running user processes."""
        procs = self.enumerate_processes()
        if not procs:
            return {"nproc": 0, "avg_threads": 0.0, "avg_handles": 0.0, "total_handles": 0}

        total_threads = sum(p["num_threads"] for p in procs)
        total_handles = sum(p["num_handles"] for p in procs)
        count = len(procs)

        return {
            "nproc": count,
            "avg_threads": float(total_threads / count),
            "avg_handles": float(total_handles / count),
            "total_handles": total_handles
        }
