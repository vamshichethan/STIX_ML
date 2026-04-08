import random

def run_pipeline(parsed_data: dict) -> dict:
    """
    Orchestrates the data flow: DB Insertion -> Graph Extraction -> ML Inference -> Trust Score.
    """
    data = parsed_data.get('data', {})
    
    # 1. DB Insertion (Mocked)
    # 2. Graph Construction (Mocked)
    
    # 3. Simulate Feature Extraction
    features = extract_features(data)
    
    # 4. ML Inference (Mocking XGBoost & GNN & Isolation Forest)
    threat_level = run_classifier(features)
    anomaly_status = run_anomaly_detector(features)
    
    # 5. Bayesian Trust
    trust_score = compute_trust_score(features)
    
    # Generate unified report
    report = {
        "summary": "STIX Data Processed Successfully",
        "threat_level": threat_level,
        "trust_score": trust_score,
        "is_anomaly": anomaly_status,
        "graph_nodes_extracted": len(data.get("objects", [])),
        "relationships_extracted": len(data.get("objects", [])) * 2, # Mock
        "raw_data_refs": data.get("id", "bundle--new")
    }
    
    return report

def extract_features(data: dict) -> list:
    """ Mock feature extracting from graph context """
    return [0.4, 0.8, 1.2]

def run_classifier(features: list) -> str:
    """ Mock XGBoost/GNN ensemble threat classification """
    levels = ["Low", "Medium", "High", "Critical"]
    return random.choice(levels)

def run_anomaly_detector(features: list) -> bool:
    """ Mock Isolation Forest anomaly detection """
    return random.random() > 0.85

def compute_trust_score(features: list) -> float:
    """ Mock Bayesian Network trust score (0.0 to 1.0) """
    return round(random.uniform(0.3, 0.98), 2)
