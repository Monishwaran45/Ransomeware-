import os
import joblib
import yaml
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Union

class RansomwarePredictor:
    """
    Production-safe predictor enforcing exact 30-feature schema for Ransomware Detection
    trained on the CIC-MalMem-2022 dataset.
    """
    
    def __init__(
        self,
        model_path: str = "models/best_model.pkl",
        feature_names_path: str = "models/feature_names.pkl",
        config_path: str = "config.yaml"
    ):
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Risk thresholds
        risk_cfg = self.config.get("thresholds", {}).get("risk", {})
        self.low_max = risk_cfg.get("low_max", 0.30)
        self.medium_max = risk_cfg.get("medium_max", 0.70)
        
        # Load model and feature names
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found at {model_path}")
        if not os.path.exists(feature_names_path):
            raise FileNotFoundError(f"Feature names file not found at {feature_names_path}")
            
        self.model = joblib.load(model_path)
        self.feature_names: List[str] = joblib.load(feature_names_path)
        self.expected_num_features = len(self.feature_names)
        
        # Label mapping verification
        self.classes_ = getattr(self.model, "classes_", np.array([0, 1]))

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                return yaml.safe_load(f)
        return {}

    def validate_features(self, features: Union[pd.DataFrame, pd.Series, dict, np.ndarray]) -> pd.DataFrame:
        """
        Validates that input features match the exact 30 features required by the model in order.
        Raises ValueError on count, missing, or order mismatch.
        """
        if isinstance(features, dict):
            df = pd.DataFrame([features])
        elif isinstance(features, pd.Series):
            df = pd.DataFrame([features.to_dict()])
        elif isinstance(features, np.ndarray):
            if features.ndim == 1:
                features = features.reshape(1, -1)
            if features.shape[1] != self.expected_num_features:
                raise ValueError(
                    f"Feature dimension mismatch: Expected {self.expected_num_features} features, got {features.shape[1]}."
                )
            df = pd.DataFrame(features, columns=self.feature_names)
        elif isinstance(features, pd.DataFrame):
            df = features.copy()
        else:
            raise TypeError(f"Unsupported features input type: {type(features)}")

        # Check missing column names if DataFrame/Dict
        missing_cols = [c for c in self.feature_names if c not in df.columns]
        if missing_cols:
            raise ValueError(
                f"Missing required feature columns ({len(missing_cols)}): {missing_cols[:5]}..."
            )

        # Enforce exact column selection and order
        df_validated = df[self.feature_names]
        
        if df_validated.shape[1] != self.expected_num_features:
            raise ValueError(
                f"Feature count mismatch: Expected {self.expected_num_features}, got {df_validated.shape[1]}"
            )

        return df_validated

    def predict_proba(self, features: Union[pd.DataFrame, pd.Series, dict, np.ndarray]) -> np.ndarray:
        """Returns ransomware probabilities for validated feature inputs."""
        df_val = self.validate_features(features)
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(df_val)
            # Ransomware is positive class (class 1)
            return probs[:, 1]
        else:
            # Fallback to decision function or binary predictions
            preds = self.model.predict(df_val)
            return preds.astype(float)

    def predict(self, features: Union[pd.DataFrame, pd.Series, dict, np.ndarray]) -> List[str]:
        """Returns predicted class labels ('Benign' or 'Ransomware')."""
        probs = self.predict_proba(features)
        labels = ["Ransomware" if p >= 0.5 else "Benign" for p in probs]
        return labels

    def predict_detailed(self, features: Union[pd.DataFrame, pd.Series, dict, np.ndarray]) -> List[Dict[str, Any]]:
        """
        Returns structured details for each prediction row:
        [
            {
                "prediction": "Benign" or "Ransomware",
                "probability": float,
                "risk_level": "LOW" | "MEDIUM" | "HIGH"
            }
        ]
        """
        df_val = self.validate_features(features)
        probs = self.predict_proba(df_val)
        
        results = []
        for p in probs:
            if p < self.low_max:
                risk = "LOW"
            elif p < self.medium_max:
                risk = "MEDIUM"
            else:
                risk = "HIGH"
                
            pred_label = "Ransomware" if p >= 0.5 else "Benign"
            
            results.append({
                "prediction": pred_label,
                "probability": float(p),
                "risk_level": risk
            })
            
        return results
