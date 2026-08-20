# SHAP Feature Importance Summary

## Top 10 Most Important Features (Tuned Random Forest)

| Rank | Feature Name | Mean absolute SHAP Score | Feature Description |
|------|--------------|-------------------------|---------------------|
| 1 | `dlllist.avg_dlls_per_proc` | 0.058089 | Average number of DLLs loaded per running process. |
| 2 | `svcscan.nservices` | 0.049428 | Total count of registered Windows services. |
| 3 | `svcscan.shared_process_services` | 0.041748 | Memory forensic metric extracted from process/system structures. |
| 4 | `svcscan.kernel_drivers` | 0.037624 | Memory forensic metric extracted from process/system structures. |
| 5 | `handles.avg_handles_per_proc` | 0.027153 | Average handle count per process. |
| 6 | `handles.nevent` | 0.024604 | Count of synchronization event handles. |
| 7 | `pslist.avg_handlers` | 0.022735 | Average number of process handles allocated across running processes. |
| 8 | `handles.nmutant` | 0.014712 | Count of mutex (mutant) synchronization handles. |
| 9 | `handles.nthread` | 0.013725 | Count of active thread handles in memory. |
| 10 | `handles.nsection` | 0.013379 | Count of shared memory section handles. |

## Interpretation
1. **Handle and DLL Statistics** (`handles.nhandles`, `dlllist.ndlls`, `handles.nfile`, `handles.nkey`):
   Ransomware activity heavily manipulates system resources—opening thousands of file handles, registry keys, and loading specialized DLLs during encryption routines.
2. **Stealth and Injection Indicators** (`ldrmodules.not_in_load`, `malfind.commitCharge`):
   Unlinked DLL modules and unallocated executable memory pages (detected by Volatility malfind) provide strong discriminative signals between benign memory dumps and ransomware-infected memory dumps.
