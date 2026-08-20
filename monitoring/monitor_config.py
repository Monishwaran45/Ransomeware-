"""
Configuration & taxonomy for CIC-MalMem-2022 30-feature real-time monitoring system.
Categorizes features by source and user-mode collectability on Windows.
"""

from typing import Dict, List, Any

# 30 Selected Features Categorization Taxonomy
FEATURE_TAXONOMY: Dict[str, Dict[str, Any]] = {
    "pslist.avg_threads": {
        "category": "Process Statistics",
        "user_mode_collectable": True,
        "description": "Average thread count across running processes"
    },
    "pslist.avg_handlers": {
        "category": "Process Statistics",
        "user_mode_collectable": True,
        "description": "Average handle count per process"
    },
    "dlllist.ndlls": {
        "category": "DLL Statistics",
        "user_mode_collectable": True,
        "description": "Total number of loaded DLL modules"
    },
    "dlllist.avg_dlls_per_proc": {
        "category": "DLL Statistics",
        "user_mode_collectable": True,
        "description": "Average DLLs loaded per process"
    },
    "handles.nhandles": {
        "category": "Handle Statistics",
        "user_mode_collectable": True,
        "description": "Total system handle count"
    },
    "handles.avg_handles_per_proc": {
        "category": "Handle Statistics",
        "user_mode_collectable": True,
        "description": "Average handle count per process"
    },
    "handles.nfile": {
        "category": "Handle Statistics",
        "user_mode_collectable": False,
        "description": "File handle count (requires administrative handle scan)"
    },
    "handles.nevent": {
        "category": "Handle Statistics",
        "user_mode_collectable": False,
        "description": "Event object handle count"
    },
    "handles.nkey": {
        "category": "Handle Statistics",
        "user_mode_collectable": False,
        "description": "Registry key handle count"
    },
    "handles.nthread": {
        "category": "Handle Statistics",
        "user_mode_collectable": False,
        "description": "Thread object handle count"
    },
    "handles.nsemaphore": {
        "category": "Handle Statistics",
        "user_mode_collectable": False,
        "description": "Semaphore handle count"
    },
    "handles.ntimer": {
        "category": "Handle Statistics",
        "user_mode_collectable": False,
        "description": "Timer handle count"
    },
    "handles.nsection": {
        "category": "Handle Statistics",
        "user_mode_collectable": False,
        "description": "Shared section handle count"
    },
    "handles.nmutant": {
        "category": "Handle Statistics",
        "user_mode_collectable": False,
        "description": "Mutex handle count"
    },
    "ldrmodules.not_in_load": {
        "category": "LDR Stealth Modules",
        "user_mode_collectable": False,
        "description": "Unlinked modules in Load order (requires Volatility memory analysis)"
    },
    "ldrmodules.not_in_init": {
        "category": "LDR Stealth Modules",
        "user_mode_collectable": False,
        "description": "Unlinked modules in Init order"
    },
    "ldrmodules.not_in_mem": {
        "category": "LDR Stealth Modules",
        "user_mode_collectable": False,
        "description": "Unlinked modules in Memory list"
    },
    "ldrmodules.not_in_load_avg": {
        "category": "LDR Stealth Modules",
        "user_mode_collectable": False,
        "description": "Average unlinked load modules"
    },
    "ldrmodules.not_in_init_avg": {
        "category": "LDR Stealth Modules",
        "user_mode_collectable": False,
        "description": "Average unlinked init modules"
    },
    "ldrmodules.not_in_mem_avg": {
        "category": "LDR Stealth Modules",
        "user_mode_collectable": False,
        "description": "Average unlinked memory modules"
    },
    "malfind.commitCharge": {
        "category": "Code Injection Statistics",
        "user_mode_collectable": False,
        "description": "Memory commit charge for injected executable regions"
    },
    "malfind.uniqueInjections": {
        "category": "Code Injection Statistics",
        "user_mode_collectable": False,
        "description": "Unique code injection regions (Volatility malfind)"
    },
    "psxview.not_in_csrss_handles_false_avg": {
        "category": "Cross-View Discrepancies",
        "user_mode_collectable": False,
        "description": "Hidden process detection via CSRSS handle table discrepancy"
    },
    "psxview.not_in_deskthrd_false_avg": {
        "category": "Cross-View Discrepancies",
        "user_mode_collectable": False,
        "description": "Hidden process detection via desktop thread table"
    },
    "svcscan.nservices": {
        "category": "Service Statistics",
        "user_mode_collectable": True,
        "description": "Total Windows service count"
    },
    "svcscan.kernel_drivers": {
        "category": "Service Statistics",
        "user_mode_collectable": False,
        "description": "Kernel driver service count"
    },
    "svcscan.process_services": {
        "category": "Service Statistics",
        "user_mode_collectable": True,
        "description": "User-mode process service count"
    },
    "svcscan.shared_process_services": {
        "category": "Service Statistics",
        "user_mode_collectable": True,
        "description": "Shared process service count"
    },
    "svcscan.nactive": {
        "category": "Service Statistics",
        "user_mode_collectable": True,
        "description": "Active running service count"
    },
    "callbacks.ncallbacks": {
        "category": "Kernel Callbacks",
        "user_mode_collectable": False,
        "description": "Kernel callback routines (requires driver/kernel memory access)"
    }
}

ALL_30_FEATURES: List[str] = list(FEATURE_TAXONOMY.keys())
UNAVAILABLE_USER_MODE_FEATURES: List[str] = [
    f for f, meta in FEATURE_TAXONOMY.items() if not meta["user_mode_collectable"]
]
