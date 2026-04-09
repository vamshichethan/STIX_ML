import hashlib
import json

def run_pipeline(parsed_data: dict) -> dict:
    """
    Orchestrates the data flow: DB Insertion -> Graph Extraction -> ML Inference -> Trust Score.
    """
    data = parsed_data.get('data', {})
    
    # 1. DB Insertion (Mocked)
    # 2. Graph Construction (Mocked)
    
    # Generate a seed from data to make it deterministic
    data_str = json.dumps(data, sort_keys=True)
    data_hash = int(hashlib.md5(data_str.encode()).hexdigest(), 16)
    
    # 3. Simulate Feature Extraction
    features = extract_features(data)
    
    # 4. ML Inference (Mocking XGBoost & GNN & Isolation Forest)
    threat_level = determine_threat_level(data, data_hash)
    anomaly_status = (data_hash % 100) > 85 # 15% chance of anomaly, but consistent
    
    # 5. Bayesian Trust
    trust_score = round(0.5 + (data_hash % 48) / 100.0, 2)
    
    # Generate unified report
    report = {
        "summary": "STIX Data Processed Successfully",
        "threat_level": threat_level,
        "trust_score": trust_score,
        "is_anomaly": anomaly_status,
        "graph_nodes_extracted": len(data.get("objects", [])),
        "relationships_extracted": len(data.get("objects", [])) * 2,
        "raw_data_refs": data.get("id", "bundle--new")
    }
    
    return report

def extract_features(data: dict) -> list:
    """ Mock feature extracting from graph context """
    return [0.4, 0.8, 1.2]

def determine_threat_level(data: dict, seed: int) -> str:
    """ Logic-based threat classification (Deterministic) """
    content = json.dumps(data).lower()
    
    # Higher priority keywords
    if any(k in content for k in ["critical", "zero-day", "log4shell", "apt-28", "fancy bear"]):
        return "Critical"
    if any(k in content for k in ["ransomware", "conti", "malware", "insider", "exfiltration"]):
        return "High"
    if any(k in content for k in ["phishing", "botnet", "mirai", "unauthorized"]):
        return "Medium"
    
    # Fallback to deterministic random if no keywords
    levels = ["Low", "Medium", "High", "Critical"]
    return levels[seed % 4]

def run_anomaly_detector(features: list) -> bool:
    """ Deprecated: used for backward compat if needed """
    return False

def compute_trust_score(features: list) -> float:
    """ Deprecated: used for backward compat if needed """
    return 0.5
