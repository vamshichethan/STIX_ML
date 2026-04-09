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
        'has_threat_actor': 1 if 'threat-actor' in types or 'campaign' in types else 0,
        'has_indicator': 1 if 'indicator' in types else 0,
        'has_malware': 1 if 'malware' in types else 0,
        'has_infrastructure': 1 if 'infrastructure' in types else 0,
        'description_len': len(str(objects))
    }
    return features

def train():
    print("Starting Advanced Model Training...")
    
    # Define current refined sample data files and their expected labels
    # 0: Low, 1: Medium, 2: High, 3: Critical
    samples_dir = os.path.join(os.path.dirname(__file__), "../../stix_samples")
    label_map = {
        "01_apt_adv_21.json": 3,
        "02_ransomware_21.json": 2,
        "03_phishing_20.json": 0,
        "04_botnet_20.json": 2,
        "05_malformed_recovery.json": 0
    }
    
    data = []
    labels = []
    
    # 1. Load samples and extract features
    for filename, label in label_map.items():
        path = os.path.join(samples_dir, filename)
        if os.path.exists(path):
            with open(path, 'r') as f:
                try:
                    bundle = json.load(f)
                    features = extract_features(bundle)
                    
                    # Create variations for robust training
                    for i in range(50): 
                        f_var = features.copy()
                        f_var['num_objects'] += np.random.randint(-1, 2)
                        f_var['description_len'] += np.random.randint(-100, 101)
                        data.append(list(f_var.values()))
                        labels.append(label)
                except:
                    continue

    # 2. Add SYNTHETIC NOISE / BENIGN DATA
    for i in range(100):
        noise = [
            np.random.randint(1, 3), # num_objects
            0, # has_threat_actor
            0, # has_indicator
            0, # has_malware
            0, # has_infrastructure
            np.random.randint(50, 400) # description_len
        ]
        data.append(noise)
        labels.append(0)

    X = np.array(data)
    y = np.array(labels)
    
    # 3. Train Random Forest
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Using more estimators for better generalization
    clf = RandomForestClassifier(n_estimators=150, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)
    
    # 4. Save Model
    models_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(models_dir, exist_ok=True)
    model_save_path = os.path.join(models_dir, "threat_classifier.joblib")
    joblib.dump(clf, model_save_path)
    
    print("=" * 60)
    print(f"Model successfully trained and saved to: {model_save_path}")
    print(f"Final Validation Accuracy: {clf.score(X_test, y_test):.2%}")
    print("=" * 60)

if __name__ == "__main__":
    train()
