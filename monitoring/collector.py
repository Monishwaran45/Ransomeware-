import pandas as pd
import numpy as np
import joblib
from typing import Dict, Any, Generator, Tuple, Optional
from monitoring.feature_extractor import FeatureExtractor
from monitoring.monitor_config import ALL_30_FEATURES

class VolatilityDumpAdapter:
    """
    Placeholder adapter for integration with Volatility 3 memory acquisition framework.
    Extracts true CIC-MalMem-2022 memory forensic features from raw RAM dumps (.raw / .dmp).
    """
    def __init__(self, dump_path: Optional[str] = None):
        self.dump_path = dump_path

    def is_available(self) -> bool:
        return self.dump_path is not None

    def extract_all_30_features(self) -> Dict[str, float]:
        if not self.is_available():
            raise NotImplementedError(
                "Live Volatility kernel acquisition adapter is uninitialized. "
                "A raw memory dump (.raw/.dmp) and Volatility 3 standalone executable are required."
            )
        # Dummy placeholder structure for advanced memory dump integration
        return {feat: 0.0 for feat in ALL_30_FEATURES}

class DataCollector:
    """
    Unified Data Collector supporting Replay mode, Live user-mode sampling,
    and Advanced Volatility memory dump adapters.
    """

    def __init__(self, dataset_csv_path: str = "Obfuscated-MalMem2022.csv"):
        self.extractor = FeatureExtractor()
        self.dataset_csv_path = dataset_csv_path
        self.volatility_adapter = VolatilityDumpAdapter()

    def get_replay_sample(self, row_index: int = 0) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Loads a single feature vector from the test dataset for offline replay testing."""
        feature_df = pd.read_csv("data/selected_features.csv")
        feature_names = feature_df["Feature"].tolist()

        try:
            X_test = joblib.load("data/processed/X_test.pkl")
            y_test = joblib.load("data/processed/y_test.pkl")
            idx = row_index % len(X_test)
            
            if isinstance(X_test, pd.DataFrame):
                vec_df = X_test.iloc[[idx]][feature_names]
            else:
                vec_df = pd.DataFrame([X_test[idx]], columns=feature_names)

            label_val = y_test.iloc[idx] if hasattr(y_test, "iloc") else y_test[idx]
            label_str = "Ransomware" if (label_val == 1 or str(label_val).lower() in ["1", "ransomware", "malware"]) else "Benign"

            meta = {
                "source": "Processed X_test.pkl Replay",
                "row_index": idx,
                "original_label": label_str
            }
            return vec_df, meta
        except Exception:
            raw_df = pd.read_csv(self.dataset_csv_path)
            sample_row = raw_df.iloc[row_index]
            vec_df = pd.DataFrame([sample_row[feature_names]])
            meta = {
                "source": "CIC-MalMem-2022 Dataset Replay",
                "row_index": row_index,
                "original_label": sample_row.get("Category", sample_row.get("Class", "Unknown"))
            }
            return vec_df, meta

    def replay_stream(self, max_samples: int = 10) -> Generator[Tuple[pd.DataFrame, Dict[str, Any]], None, None]:
        """Streams dataset rows sequentially for pipeline replay testing."""
        for i in range(max_samples):
            yield self.get_replay_sample(i)

    def collect_live_vector(self) -> Tuple[Optional[pd.DataFrame], Dict[str, Any]]:
        """
        Attempts to collect live feature vector.
        Explicitly fails and reports missing features if run in pure user-mode without memory dump.
        """
        if self.volatility_adapter.is_available():
            mem_features = self.volatility_adapter.extract_all_30_features()
            return pd.DataFrame([mem_features])[ALL_30_FEATURES], {"source": "volatility_adapter"}

        # Attempt user-mode collection, which will fail gracefully with full diagnostic info
        return self.extractor.build_feature_vector_with_fallback(fallback_vector=None)
