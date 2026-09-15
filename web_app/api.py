import os
import time
import json
import psutil
import joblib
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.predictor import RansomwarePredictor
from monitoring.collector import DataCollector
from monitoring.logger import MonitoringLogger
from monitoring.alert import AlertSystem
from monitoring.feature_extractor import FeatureExtractor

# Initialize App
app = FastAPI(
    title="Cyber Defense SOC REST API",
    description="Dynamic Production-grade Memory Forensics and Behavioral Detection System",
    version="2.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Base directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "web_app", "static")
FIGURES_DIR = os.path.join(BASE_DIR, "reports", "figures")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# Mount static files and figures
if os.path.exists(FIGURES_DIR):
    app.mount("/figures", StaticFiles(directory=FIGURES_DIR), name="figures")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Initialize ML & Monitoring Engines
predictor = RansomwarePredictor(
    model_path="models/best_model.pkl",
    feature_names_path="models/feature_names.pkl",
    config_path="config.yaml"
)
collector = DataCollector(dataset_csv_path="Obfuscated-MalMem2022.csv")
logger = MonitoringLogger()
alert_system = AlertSystem()
extractor = FeatureExtractor()

# Load Test Dataset Statistics Dynamically
_FEATURE_STATS = {}
_DYNAMIC_PRESETS = {}

try:
    X_test = joblib.load("data/processed/X_test.pkl")
    y_test = joblib.load("data/processed/y_test.pkl")
    if not isinstance(X_test, pd.DataFrame):
        df_X = pd.DataFrame(X_test, columns=predictor.feature_names)
    else:
        df_X = X_test

    means = df_X.mean().to_dict()
    stds = df_X.std().replace(0, 1.0).to_dict()
    mins = df_X.min().to_dict()
    maxs = df_X.max().to_dict()

    # Calculate model feature importances
    if hasattr(predictor.model, "feature_importances_"):
        raw_importances = dict(zip(predictor.feature_names, [float(x) for x in predictor.model.feature_importances_]))
    else:
        raw_importances = {f: 1.0 / len(predictor.feature_names) for f in predictor.feature_names}

    for feat in predictor.feature_names:
        _FEATURE_STATS[feat] = {
            "mean": float(means.get(feat, 0.0)),
            "std": float(stds.get(feat, 1.0)),
            "min": float(mins.get(feat, 0.0)),
            "max": float(maxs.get(feat, 100.0)),
            "importance": float(raw_importances.get(feat, 0.0))
        }

    # Dynamically extract genuine presets from test data
    # 1. Benign Baseline Sample (prob < 0.01)
    for idx in range(len(y_test)):
        if y_test.iloc[idx] == 0:
            row_df = df_X.iloc[[idx]]
            res = predictor.predict_detailed(row_df)[0]
            if res["probability"] < 0.01:
                _DYNAMIC_PRESETS["benign_baseline"] = {
                    "key": "benign_baseline",
                    "name": "Benign Host Baseline",
                    "description": f"Verified benign Windows host process (Dataset row #{idx}).",
                    "expected": "Benign",
                    "badge_type": "LOW",
                    "values": {k: round(float(v), 4) for k, v in row_df.iloc[0].to_dict().items()}
                }
                break

    # 2. High-Impact Ransomware Attack (prob > 0.95)
    for idx in range(len(y_test)):
        if y_test.iloc[idx] == 1:
            row_df = df_X.iloc[[idx]]
            res = predictor.predict_detailed(row_df)[0]
            if res["probability"] > 0.95:
                _DYNAMIC_PRESETS["ransomware_high_impact"] = {
                    "key": "ransomware_high_impact",
                    "name": "Aggressive Ransomware Attack",
                    "description": f"Active ransomware memory vector with high handle and DLL linkage disruption (Dataset row #{idx}).",
                    "expected": "Ransomware",
                    "badge_type": "HIGH",
                    "values": {k: round(float(v), 4) for k, v in row_df.iloc[0].to_dict().items()}
                }
                break

    # 3. Stealth / Fileless Vector (0.70 <= prob <= 0.90)
    for idx in range(len(y_test)):
        if y_test.iloc[idx] == 1:
            row_df = df_X.iloc[[idx]]
            res = predictor.predict_detailed(row_df)[0]
            if 0.70 <= res["probability"] <= 0.95:
                _DYNAMIC_PRESETS["fileless_injection_stealth"] = {
                    "key": "fileless_injection_stealth",
                    "name": "Obfuscated Fileless Injected Vector",
                    "description": f"Stealthy unlinked memory injection vector (Dataset row #{idx}).",
                    "expected": "Ransomware",
                    "badge_type": "MEDIUM",
                    "values": {k: round(float(v), 4) for k, v in row_df.iloc[0].to_dict().items()}
                }
                break

except Exception as e:
    print(f"[!] Warning: Could not compute dynamic dataset statistics: {e}")


# Schemas
class PredictRequest(BaseModel):
    features: Dict[str, float]
    process_context: Optional[str] = "Forensic Studio Evaluation"
    feature_source: Optional[str] = "Web UI Inspector"


class BatchReplayRequest(BaseModel):
    num_samples: int = 5
    start_index: int = 0


@app.get("/")
def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Cyber Defense SOC API is running."}


@app.get("/api/status")
def get_system_status():
    """Returns dynamic system status, model information, and thresholds."""
    avail_info = extractor.check_feature_availability()
    return {
        "status": "ONLINE",
        "model_name": type(predictor.model).__name__,
        "features_count": predictor.expected_num_features,
        "feature_names": predictor.feature_names,
        "thresholds": {
            "low_max": predictor.low_max,
            "medium_max": predictor.medium_max
        },
        "feature_availability": avail_info,
        "dataset_available": os.path.exists(collector.dataset_csv_path) or os.path.exists("data/processed/X_test.pkl"),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }


@app.get("/api/features")
def get_dynamic_features():
    """
    Returns dynamically categorized feature metadata, statistics (mean/std/min/max),
    and importance rankings computed directly from the trained model and dataset.
    """
    category_map = {
        "pslist": "1. Process & Thread Metrics",
        "psxview": "1. Process & Thread Metrics",
        "dlllist": "2. DLL Linkage Metrics",
        "handles": "3. Handle Allocation Forensics",
        "ldrmodules": "4. Volatility Stealth Flags",
        "malfind": "4. Injected Code Indicators",
        "svcscan": "5. Kernel Services",
        "callbacks": "5. Kernel Callbacks"
    }

    categorized = {}
    feature_list = []

    for feat in predictor.feature_names:
        prefix = feat.split(".")[0]
        cat_name = category_map.get(prefix, "Other Forensic Metrics")
        
        stats = _FEATURE_STATS.get(feat, {"mean": 0.0, "std": 1.0, "min": 0.0, "max": 100.0, "importance": 0.0})
        
        feat_info = {
            "name": feat,
            "prefix": prefix,
            "category": cat_name,
            "mean": stats["mean"],
            "std": stats["std"],
            "min": stats["min"],
            "max": stats["max"],
            "importance": stats["importance"]
        }
        
        feature_list.append(feat_info)
        
        if cat_name not in categorized:
            categorized[cat_name] = []
        categorized[cat_name].append(feat_info)

    # Sort categories by importance
    return {
        "total_features": len(predictor.feature_names),
        "categories": categorized,
        "features": feature_list
    }


@app.get("/api/presets")
def get_feature_presets():
    """Returns dynamic preset forensic vectors extracted from genuine dataset samples."""
    return _DYNAMIC_PRESETS


@app.post("/api/predict")
def predict_vector(req: PredictRequest):
    """
    Validates the 30-feature vector, performs model inference, assesses risk,
    dynamically evaluates feature anomalies using z-scores, and triggers alerts.
    """
    try:
        detailed = predictor.predict_detailed(req.features)
        res = detailed[0]
        
        # Log prediction
        logger.log_prediction(
            prediction_result=res,
            process_context=req.process_context,
            feature_source=req.feature_source,
            monitoring_mode="WEB_INSPECTOR"
        )
        
        # Trigger alert if Ransomware / HIGH Risk
        alert_triggered = False
        if res["risk_level"] == "HIGH" or res["prediction"] == "Ransomware":
            alert_system.trigger_alert(
                prediction_result=res,
                process_context=req.process_context,
                feature_source=req.feature_source
            )
            alert_triggered = True

        # Dynamically rank top discriminative indicators based on model importance and deviation
        contributions = []
        for feat, val in req.features.items():
            stats = _FEATURE_STATS.get(feat, {"mean": 0.0, "std": 1.0, "importance": 0.0})
            z_score = abs(val - stats["mean"]) / stats["std"]
            score = z_score * stats["importance"]
            is_anomalous = z_score > 2.0 or (val > stats["mean"] + stats["std"] and stats["importance"] > 0.05)
            
            contributions.append({
                "feature": feat,
                "value": round(float(val), 4),
                "z_score": round(float(z_score), 2),
                "importance": stats["importance"],
                "score": score,
                "elevated": bool(is_anomalous)
            })

        contributions.sort(key=lambda x: x["score"], reverse=True)

        return {
            "prediction": res["prediction"],
            "probability": round(res["probability"], 4),
            "confidence_percent": round(res["probability"] * 100, 2),
            "risk_level": res["risk_level"],
            "alert_triggered": alert_triggered,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "top_features": contributions[:6]
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/replay/sample")
def get_replay_sample(index: int = Query(0, ge=0)):
    """Fetches a single sample from dataset and runs instant evaluation."""
    try:
        vec_df, meta = collector.get_replay_sample(index)
        detailed = predictor.predict_detailed(vec_df)
        res = detailed[0]
        
        process_ctx = f"Replay Row #{meta['row_index']} ({meta['original_label']})"
        logger.log_prediction(
            prediction_result=res,
            process_context=process_ctx,
            feature_source=meta['source'],
            monitoring_mode="WEB_REPLAY"
        )
        
        alert_triggered = False
        if res["risk_level"] == "HIGH" or res["prediction"] == "Ransomware":
            alert_system.trigger_alert(
                prediction_result=res,
                process_context=process_ctx,
                feature_source=meta['source']
            )
            alert_triggered = True

        features_dict = vec_df.iloc[0].to_dict()

        return {
            "meta": meta,
            "prediction": res["prediction"],
            "probability": round(res["probability"], 4),
            "confidence_percent": round(res["probability"] * 100, 2),
            "risk_level": res["risk_level"],
            "ground_truth": meta.get("original_label", "Unknown"),
            "is_correct": (res["prediction"].lower() in str(meta.get("original_label", "")).lower()),
            "alert_triggered": alert_triggered,
            "features": features_dict,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/replay/batch")
def run_batch_replay(req: BatchReplayRequest):
    """Executes a batch replay sequence and returns the evaluated trace."""
    results = []
    for i in range(req.start_index, req.start_index + req.num_samples):
        try:
            vec_df, meta = collector.get_replay_sample(i)
            detailed = predictor.predict_detailed(vec_df)
            res = detailed[0]
            
            process_ctx = f"Replay Row #{meta['row_index']} ({meta['original_label']})"
            logger.log_prediction(
                prediction_result=res,
                process_context=process_ctx,
                feature_source=meta['source'],
                monitoring_mode="WEB_BATCH"
            )
            
            alert_triggered = False
            if res["risk_level"] == "HIGH" or res["prediction"] == "Ransomware":
                alert_system.trigger_alert(
                    prediction_result=res,
                    process_context=process_ctx,
                    feature_source=meta['source']
                )
                alert_triggered = True

            results.append({
                "sample_index": i,
                "source": meta["source"],
                "ground_truth": meta.get("original_label", "Unknown"),
                "prediction": res["prediction"],
                "probability": round(res["probability"], 4),
                "risk_level": res["risk_level"],
                "alert_triggered": alert_triggered,
                "is_match": (res["prediction"].lower() in str(meta.get("original_label", "")).lower())
            })
        except Exception as e:
            results.append({
                "sample_index": i,
                "error": str(e)
            })

    return {
        "batch_size": len(results),
        "start_index": req.start_index,
        "results": results,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }


@app.get("/api/reports/benchmarks")
def get_benchmarks():
    """Returns dynamic model comparison benchmark metrics."""
    eval_json_path = os.path.join(REPORTS_DIR, "evaluation_report.json")
    if os.path.exists(eval_json_path):
        with open(eval_json_path, "r") as f:
            return json.load(f)
    return {"error": "Evaluation report not found"}


@app.get("/api/reports/shap")
def get_shap_summary():
    """Returns dynamic SHAP importance rankings directly from trained model."""
    figures = {
        "shap_bar": "/figures/shap_bar.png",
        "shap_beeswarm": "/figures/shap_beeswarm.png",
        "shap_waterfall": "/figures/shap_waterfall.png",
        "confusion_matrix": "/figures/confusion_matrix.png",
        "roc_curve": "/figures/roc_curve.png",
        "model_comparison": "/figures/model_comparison.png",
        "precision_recall_curve": "/figures/precision_recall_curve.png"
    }

    # Extract dynamic feature rankings from model
    ranked = sorted(_FEATURE_STATS.items(), key=lambda x: x[1]["importance"], reverse=True)
    top_features = []
    
    for rank, (feat, st) in enumerate(ranked[:6], start=1):
        top_features.append({
            "feature": feat,
            "importance_rank": rank,
            "importance_score": round(st["importance"], 6),
            "mean": round(st["mean"], 2),
            "std": round(st["std"], 2),
            "insight": f"Impact weight {st['importance']*100:.2f}% in the decision forest."
        })

    return {
        "figures": figures,
        "top_features": top_features,
        "explainer_model": type(predictor.model).__name__,
        "num_features": len(predictor.feature_names)
    }


@app.get("/api/stats")
def get_soc_stats():
    """Calculates aggregate statistics from predictions and alerts logs."""
    total_predictions = 0
    ransomware_count = 0
    benign_count = 0
    risk_distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    recent_alerts = []
    
    pred_path = os.path.join(LOGS_DIR, "predictions.csv")
    if os.path.exists(pred_path):
        try:
            df_pred = pd.read_csv(pred_path)
            total_predictions = len(df_pred)
            if "prediction" in df_pred.columns:
                ransomware_count = int((df_pred["prediction"] == "Ransomware").sum())
                benign_count = int((df_pred["prediction"] == "Benign").sum())
            if "risk_level" in df_pred.columns:
                risk_counts = df_pred["risk_level"].value_counts().to_dict()
                for k in ["LOW", "MEDIUM", "HIGH"]:
                    risk_distribution[k] = int(risk_counts.get(k, 0))
        except Exception:
            pass

    timeline = []
    alerts_path = os.path.join(LOGS_DIR, "alerts.csv")
    if os.path.exists(alerts_path):
        try:
            df_alert = pd.read_csv(alerts_path)
            recent_alerts = df_alert.tail(10).to_dict(orient="records")
        except Exception:
            pass

    if os.path.exists(pred_path):
        try:
            if "probability" in df_pred.columns:
                recent_preds = df_pred.tail(15)
                for _, r in recent_preds.iterrows():
                    ts = str(r.get("timestamp", ""))
                    time_label = ts.split(" ")[1] if " " in ts else ts
                    timeline.append({
                        "time": time_label or "Now",
                        "probability": round(float(r["probability"]) * 100, 1),
                        "prediction": str(r.get("prediction", "Benign")),
                        "risk_level": str(r.get("risk_level", "LOW"))
                    })
        except Exception:
            pass

    return {
        "total_scans": total_predictions,
        "ransomware_detected": ransomware_count,
        "benign_cleared": benign_count,
        "threat_ratio": round((ransomware_count / total_predictions * 100) if total_predictions > 0 else 0, 2),
        "risk_distribution": risk_distribution,
        "total_alerts": len(recent_alerts),
        "recent_alerts": recent_alerts,
        "timeline": timeline,
        "system_health": "SECURE" if risk_distribution["HIGH"] == 0 else "ELEVATED_THREAT"
    }


@app.get("/api/logs/predictions")
def get_prediction_logs(limit: int = Query(50, ge=1, le=500)):
    pred_path = os.path.join(LOGS_DIR, "predictions.csv")
    if not os.path.exists(pred_path):
        return {"total": 0, "logs": []}
    try:
        df = pd.read_csv(pred_path)
        records = df.tail(limit).to_dict(orient="records")
        return {"total": len(df), "logs": list(reversed(records))}
    except Exception as e:
        return {"error": str(e), "logs": []}


@app.get("/api/logs/alerts")
def get_alert_logs(limit: int = Query(50, ge=1, le=500)):
    alert_path = os.path.join(LOGS_DIR, "alerts.csv")
    if not os.path.exists(alert_path):
        return {"total": 0, "logs": []}
    try:
        df = pd.read_csv(alert_path)
        records = df.tail(limit).to_dict(orient="records")
        return {"total": len(df), "logs": list(reversed(records))}
    except Exception as e:
        return {"error": str(e), "logs": []}


@app.get("/api/logs/behavioral")
def get_behavioral_logs(limit: int = Query(50, ge=1, le=500)):
    beh_path = os.path.join(LOGS_DIR, "behavioral_events.csv")
    if not os.path.exists(beh_path):
        return {"total": 0, "logs": []}
    try:
        df = pd.read_csv(beh_path)
        records = df.tail(limit).to_dict(orient="records")
        return {"total": len(df), "logs": list(reversed(records))}
    except Exception as e:
        return {"error": str(e), "logs": []}


@app.post("/api/logs/clear")
def clear_logs():
    for log_name in ["predictions.csv", "alerts.csv", "behavioral_events.csv"]:
        path = os.path.join(LOGS_DIR, log_name)
        if os.path.exists(path):
            with open(path, "w") as f:
                if log_name == "predictions.csv":
                    f.write("timestamp,prediction,probability,risk_level,process_context,feature_source,monitoring_mode\n")
                elif log_name == "alerts.csv":
                    f.write("timestamp,prediction,confidence,risk_level,process_context,feature_source\n")
                elif log_name == "behavioral_events.csv":
                    f.write("timestamp,window_seconds,file_events_total,file_created,file_modified,file_deleted,cpu_percent,memory_percent,running_processes\n")
    return {"message": "Logs reset successfully"}


@app.get("/api/behavioral/sample")
def sample_live_behavior():
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        pids = len(psutil.pids())
        top_procs = []
        for p in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'num_threads', 'num_handles']), key=lambda x: x.info.get('cpu_percent', 0) or 0, reverse=True)[:5]:
            try:
                top_procs.append({
                    "pid": p.info['pid'],
                    "name": p.info['name'],
                    "cpu": round(p.info['cpu_percent'] or 0, 1),
                    "memory": round(p.info['memory_percent'] or 0, 1),
                    "threads": p.info.get('num_threads', 0),
                    "handles": p.info.get('num_handles', 0)
                })
            except Exception:
                pass

        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "cpu_percent": cpu,
            "memory_percent": mem,
            "running_processes": pids,
            "top_processes": top_procs
        }
    except Exception as e:
        return {"error": str(e)}
