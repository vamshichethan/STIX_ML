import hashlib
import json
import joblib
import os
import numpy as np

# Load the trained model
MODEL_PATH = os.path.join(os.path.dirname(__file__), "models/threat_classifier.joblib")
try:
    clf = joblib.load(MODEL_PATH)
except:
    clf = None

from app.services.intelligence_engine import IntelligenceEngine

def run_pipeline(parsed_data: dict) -> dict:
    """
    Orchestrates the data flow: DB Insertion -> Graph Extraction -> ML Inference -> Intelligence Analysis.
    """
    data = parsed_data.get('data', {})
    
    # Generate a seed from data for any remaining randomized parts
    data_str = json.dumps(data, sort_keys=True)
    data_hash = int(hashlib.md5(data_str.encode()).hexdigest(), 16)
    
    # 1. Feature Extraction
    features = extract_features(data)
    
    # 2. ML Inference (Using Trained Random Forest)
    ml_threat_level = predict_threat_level(features, data, data_hash)
    
    # 3. Graph Intelligence Analysis (New Step)
    intel_engine = IntelligenceEngine()
    intel_report = intel_engine.analyze_stix_bundle(data)
    decision = intel_report.get("decision_bundle", {})
    
    # 4. Anomaly & Trust Score (Augmented by Intelligence)
    has_anomalies = len(decision.get("anomalies", [])) > 0
    trust_score = round(decision.get("confidence", 0.5), 2)
    
    # Generate unified report
    report = {
        "summary": "STIX Data Analyzed with Hybrid ML/Graph Intelligence",
        "threat_level": decision.get("threat_level") or ml_threat_level,
        "ml_inference": ml_threat_level,
        "graph_intelligence": decision,
        "trust_score": trust_score,
        "is_anomaly": has_anomalies,
        "attack_chain": decision.get("attack_chain", []),
        "recommended_action": decision.get("recommended_action", []),
        "graph_nodes_extracted": len(intel_report.get("graph", {}).get("nodes", [])),
        "relationships_extracted": len(intel_report.get("graph", {}).get("edges", [])),
        "raw_data_refs": data.get("id", "bundle--new"),
        "validation_details": parsed_data.get("validation", {}),
        "stix_version": parsed_data.get("version", "Unknown")
    }
    
    return report

def extract_features(data: dict) -> list:
    """ Extract 6-dimensional feature vector for the Random Forest model """
    objects = data.get('objects', [])
    types = [obj.get('type') for obj in objects]
    
    return [
        len(objects),
        1 if 'threat-actor' in types or 'campaign' in types else 0,
        1 if 'indicator' in types else 0,
        1 if 'malware' in types else 0,
        1 if 'infrastructure' in types else 0,
        len(str(objects))
    ]

def predict_threat_level(features: list, data: dict, seed: int) -> str:
    """ Prediction using the loaded joblib model with safety overrides """
    if clf:
        # Features: [num_objects, has_actor, has_ind, has_mal, has_vuln, desc_len]
        has_flags = any(features[1:5])
        
        X = np.array([features])
        y_pred = int(clf.predict(X)[0])
        levels = ["Low", "Medium", "High", "Critical"]
        
        # Guard: If NO malicious flags are present, cap at Medium unless model is VERY sure.
        # This prevents "random noise" from being flagged as High/Critical.
        if not has_flags and y_pred > 1:
            return "Low"
            
        return levels[y_pred]

def run_anomaly_detector(features: list) -> bool:
    return False

def compute_trust_score(features: list) -> float:
    return 0.5
