from datetime import datetime
from typing import Dict, Any

class AlertSystem:
    """
    Console & Security Alert System formatting high-risk threat alerts.
    
    SAFETY NOTE:
    Does NOT automatically terminate processes in this implementation.
    Automated response capabilities are left for future controlled extension.
    """

    def trigger_alert(
        self,
        prediction_result: Dict[str, Any],
        process_context: str = "System Memory Snapshot",
        feature_source: str = "CIC-MalMem Replay"
    ):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pred = prediction_result.get("prediction", "Ransomware")
        prob = prediction_result.get("probability", 0.0) * 100
        risk = prediction_result.get("risk_level", "HIGH")

        alert_msg = f"""
================================================================================
[ALERT] POTENTIAL RANSOMWARE DETECTED [ALERT]
================================================================================
Prediction:        {pred}
Confidence:        {prob:.2f}%
Risk Level:        {risk}
Timestamp:         {timestamp}
Process Context:   {process_context}
Feature Source:    {feature_source}
--------------------------------------------------------------------------------
Action Taken:      Alert logged to logs/alerts.csv. (No automatic process termination)
================================================================================
"""
        print(alert_msg)
