import sys
import argparse
import time
from src.predictor import RansomwarePredictor
from monitoring.collector import DataCollector
from monitoring.feature_extractor import FeatureExtractor
from monitoring.logger import MonitoringLogger
from monitoring.alert import AlertSystem
from behavior_monitoring.event_aggregator import BehavioralEventAggregator

def run_replay_mode(num_samples: int = 5):
    """
    REPLAY MODE:
    Loads CIC-MalMem-2022 feature vectors from dataset/processed test data and pushes them through
    the full production pipeline: Validation -> Predictor -> Risk Level -> Logger -> Alert.
    """
    print(f"\n==================================================")
    print(f"[>] RUNNING REPLAY MODE ({num_samples} Samples)")
    print(f"==================================================")

    predictor = RansomwarePredictor()
    collector = DataCollector()
    logger = MonitoringLogger()
    alert_sys = AlertSystem()

    for idx, (features_df, meta) in enumerate(collector.replay_stream(max_samples=num_samples)):
        print(f"\n--- Sample {idx+1}/{num_samples} [{meta['source']} - Row {meta['row_index']}] ---")
        
        # 1. Validation & Prediction
        detailed_results = predictor.predict_detailed(features_df)
        res = detailed_results[0]
        
        print(f"Prediction:  {res['prediction']}")
        print(f"Probability: {res['probability']*100:.2f}%")
        print(f"Risk Level:  {res['risk_level']}")
        
        # 2. Logging
        process_ctx = f"Replay Row #{meta['row_index']} ({meta['original_label']})"
        logger.log_prediction(
            prediction_result=res,
            process_context=process_ctx,
            feature_source=meta['source'],
            monitoring_mode="REPLAY"
        )

        # 3. Alerting if HIGH risk
        if res["risk_level"] == "HIGH" or res["prediction"] == "Ransomware":
            alert_sys.trigger_alert(
                prediction_result=res,
                process_context=process_ctx,
                feature_source=meta['source']
            )

    print("\n[+] Replay mode completed successfully. Logs written to logs/predictions.csv & logs/alerts.csv.")

def run_monitor_mode():
    """
    MONITOR MODE:
    Runs compatible live memory monitoring architecture.
    Validates feature availability and gracefully handles user-mode API limitations.
    """
    print(f"\n==================================================")
    print(f"[>] RUNNING MONITOR MODE (Live Memory Compatibility Check)")
    print(f"==================================================")

    extractor = FeatureExtractor()
    avail_info = extractor.check_feature_availability()

    print(f"Total Required CIC-MalMem Features: {avail_info['total_required']}")
    print(f"User-Mode Collectable Features:     {avail_info['collectable_count']}")
    print(f"Uncollectable Memory Features:      {avail_info['uncollectable_count']}")
    
    print("\n[!] Uncollectable User-Mode Features (Requires Volatility 3 Memory Dump Adapter):")
    for feat in avail_info['uncollectable_features']:
        print(f"  - {feat}")

    print("\n--------------------------------------------------")
    print("CRITICAL MONITORING LIMITATION:")
    print("CIC-MalMem-2022 features represent deep memory forensic metrics (LDR module lists,")
    print("malfind commit charges, kernel callbacks) extracted from raw RAM dumps.")
    print("Standard Windows user-mode APIs (psutil) CANNOT collect these 26 memory features live.")
    print("Silent substitution with unrelated live metrics is strictly prevented.")
    print("--------------------------------------------------")
    print("\nTo test the complete prediction pipeline with valid 30-feature vectors:")
    print("   python main.py --mode replay")
    print("--------------------------------------------------\n")

def run_behavioral_monitor_mode(duration: int = 15, window: int = 5):
    """
    BEHAVIORAL MONITOR MODE:
    Runs separate watchdog file observer and psutil resource sampler.
    Telemetry is logged to logs/behavioral_events.csv for separate research.
    """
    print(f"\n==================================================")
    print(f"[>] RUNNING BEHAVIORAL MONITOR MODE ({duration}s duration)")
    print(f"==================================================")

    aggregator = BehavioralEventAggregator(watch_path=".", window_seconds=window)
    aggregator.start_monitoring(duration_seconds=duration)
    print("\n[+] Behavioral telemetry saved to logs/behavioral_events.csv.")


def run_web_mode(host: str = "127.0.0.1", port: int = 8000):
    """
    WEB SOC DASHBOARD MODE:
    Launches FastAPI & Cyber Defense SOC Web Dashboard.
    """
    print(f"\n==================================================")
    print(f"[>] STARTING RANSOMWARE SOC DASHBOARD")
    print(f"[>] URL: http://{host}:{port}")
    print(f"==================================================")
    try:
        import uvicorn
        uvicorn.run("web_app.api:app", host=host, port=port, reload=False)
    except ImportError:
        print("[!] uvicorn or fastapi is missing. Run: uv pip install fastapi uvicorn")

def main():
    parser = argparse.ArgumentParser(description="Ransomware Detection & Monitoring CLI & Web System")
    parser.add_argument(
        "--mode",
        choices=["replay", "monitor", "behavioral-monitor", "web"],
        default="web",
        help="Operating mode: 'web' (SOC Dashboard UI), 'replay' (dataset test), 'monitor' (live compatibility check), 'behavioral-monitor' (watchdog/psutil logger)"
    )
    parser.add_argument("--samples", type=int, default=5, help="Number of samples to replay in replay mode")
    parser.add_argument("--duration", type=int, default=15, help="Duration in seconds for behavioral monitoring")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address for web server")
    parser.add_argument("--port", type=int, default=8000, help="Port for web server")

    args = parser.parse_args()

    if args.mode == "web":
        run_web_mode(host=args.host, port=args.port)
    elif args.mode == "replay":
        run_replay_mode(num_samples=args.samples)
    elif args.mode == "monitor":
        run_monitor_mode()
    elif args.mode == "behavioral-monitor":
        run_behavioral_monitor_mode(duration=args.duration)

if __name__ == "__main__":
    main()

