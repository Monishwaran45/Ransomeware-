import pandas as pd
from typing import Dict, Any, Tuple, List, Optional
from monitoring.monitor_config import FEATURE_TAXONOMY, ALL_30_FEATURES, UNAVAILABLE_USER_MODE_FEATURES
from monitoring.process_monitor import ProcessMonitor

class FeatureExtractor:
    """
    Extracts available CIC-MalMem-2022 compatible features from live system APIs,
    while explicitly marking uncollectable Volatility memory features.
    """

    def __init__(self):
        self.proc_monitor = ProcessMonitor()

    def check_feature_availability(self) -> Dict[str, Any]:
        """Returns analysis of collectable vs uncollectable features in user-mode."""
        collectable = [f for f, meta in FEATURE_TAXONOMY.items() if meta["user_mode_collectable"]]
        uncollectable = UNAVAILABLE_USER_MODE_FEATURES
        return {
            "total_required": len(ALL_30_FEATURES),
            "collectable_count": len(collectable),
            "uncollectable_count": len(uncollectable),
            "collectable_features": collectable,
            "uncollectable_features": uncollectable
        }

    def extract_live_user_mode_features(self) -> Dict[str, float]:
        """Extracts available metrics from user-mode APIs (psutil/Win32)."""
        summary = self.proc_monitor.get_system_process_summary()
        
        # User-mode metrics approximation where compatible
        live_features = {
            "pslist.avg_threads": summary["avg_threads"],
            "pslist.avg_handlers": summary["avg_handles"],
            "handles.nhandles": float(summary["total_handles"]),
            "handles.avg_handles_per_proc": summary["avg_handles"]
        }
        return live_features

    def build_feature_vector_with_fallback(
        self,
        fallback_vector: Optional[Dict[str, float]] = None
    ) -> Tuple[Optional[pd.DataFrame], Dict[str, Any]]:
        """
        Builds complete 30-feature vector using live metrics and documented fallback values
        (e.g., from an offline memory dump vector or dataset sample).
        
        Explicitly rejects generating a vector if required memory features are missing
        and no fallback strategy is supplied.
        """
        live_metrics = self.extract_live_user_mode_features()
        avail_info = self.check_feature_availability()
        
        if fallback_vector is None:
            # Cannot construct full vector safely without memory dump adapter/fallback
            return None, {
                "status": "FAIL",
                "reason": (
                    f"User-mode API can only collect {avail_info['collectable_count']}/{avail_info['total_required']} "
                    f"features. Missing Volatility memory forensic features: {avail_info['uncollectable_features'][:5]}... "
                    "Use --mode replay or provide a valid memory dump vector."
                ),
                "availability": avail_info
            }

        vector_dict = {}
        for feature in ALL_30_FEATURES:
            if feature in live_metrics:
                vector_dict[feature] = live_metrics[feature]
            elif feature in fallback_vector:
                vector_dict[feature] = fallback_vector[feature]
            else:
                vector_dict[feature] = 0.0

        df = pd.DataFrame([vector_dict])[ALL_30_FEATURES]
        return df, {
            "status": "SUCCESS",
            "feature_source": "hybrid_live_and_fallback",
            "availability": avail_info
        }
