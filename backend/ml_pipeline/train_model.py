import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

def extract_features(stix_bundle):
    """ Converts a STIX bundle into a feature vector """
    objects = stix_bundle.get('objects', [])
    types = [obj.get('type') for obj in objects]
    
    features = {
        'num_objects': len(objects),
        'has_threat_actor': 1 if 'threat-actor' in types else 0,
        'has_indicator': 1 if 'indicator' in types else 0,
        'has_malware': 1 if 'malware' in types else 0,
        'has_vulnerability': 1 if 'vulnerability' in types else 0,
        'description_len': len(str(objects)) # Proxy for detail complexity
    }
    return features

def train():
    print("Starting Model Training...")
    
    # Define sample data files and their expected labels
    samples_dir = os.path.join(os.path.dirname(__file__), "../../stix_samples")
    label_map = {
        "01_critical_apt.json": 3,
        "02_high_ransomware.json": 2,
        "03_medhigh_phishing.json": 2,
        "04_medium_botnet.json": 1,
        "05_medium_leak.json": 1,
        "06_low_vuln.json": 0,
        "07_info_patch.json": 0,
        "08_low_benign.json": 0,
        "09_high_insider.json": 2,
        "10_critical_zero_day.json": 3
    }
    
    data = []
    labels = []
    
    # 1. Load samples and extract features
    for filename, label in label_map.items():
        path = os.path.join(samples_dir, filename)
        if os.path.exists(path):
            with open(path, 'r') as f:
                bundle = json.load(f)
                features = extract_features(bundle)
                
                # Create synthetic variations to have more data
                for i in range(10): # 10 variations per sample
                    f_var = features.copy()
                    f_var['num_objects'] += np.random.randint(-1, 2)
                    f_var['description_len'] += np.random.randint(-50, 51)
                    data.append(list(f_var.values()))
                    labels.append(label)

    X = np.array(data)
    y = np.array(labels)
    
    # 2. Train Random Forest
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    # 3. Save Model
    os.makedirs("models", exist_ok=True)
    joblib.dump(clf, "models/threat_classifier.joblib")
    print(f"Model trained and saved to models/threat_classifier.joblib with accuracy: {clf.score(X_test, y_test):.2f}")

if __name__ == "__main__":
    train()
