import os
import sys
import json
import glob

# Setup path
workspace_root = "/Users/vamshi/Desktop/STIX_ML/backend"
if workspace_root not in sys.path:
    sys.path.append(workspace_root)

from app.services.stix_version_detector import STIXVersionDetector
from app.services.stix_validator import STIXValidator
from app.services.intelligence_engine import IntelligenceEngine

def verify_all_samples():
    detector = STIXVersionDetector()
    validator = STIXValidator()
    intel_engine = IntelligenceEngine()
    
    samples_dir = "/Users/vamshi/Desktop/STIX_ML/stix_samples"
    sample_files = sorted(glob.glob(os.path.join(samples_dir, "*")))
    sample_files = [f for f in sample_files if f.endswith((".json", ".xml"))]
    
    print("=" * 110)
    print(f"{'Sample File':<30} | {'Ver':<5} | {'Val Score':<10} | {'Threat':<10} | {'Trust':<10} | {'Recovered?'}")
    print("-" * 110)
    
    for file_path in sample_files:
        filename = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            content = f.read()
            
        # 1. Detection
        det = detector.detect(content)
        ver = det["version"]
        
        # 2. Validation
        val = validator.validate(content)
        val_score = val.get("score", 0)
        
        # 3. Intelligence (On auto-corrected data if available)
        clean_data = val.get("auto_corrected_data")
        if not clean_data:
            try:
                clean_data = json.loads(content)
            except:
                # Handle XML or other formats
                clean_data = {"id": filename, "type": "bundle", "objects": []}
        
        intel = intel_engine.analyze_stix_bundle(clean_data)
        threat = intel.get("decision_bundle", {}).get("threat_level", "N/A")
        trust = intel.get("decision_bundle", {}).get("confidence", 0.0)
        
        recovered = "YES" if val.get("recovery_notes") else "NO"
        
        print(f"{filename[:30]:<30} | {ver:<5} | {val_score:<10} | {threat:<10} | {trust:<10} | {recovered}")

    print("=" * 100)
    print("\nDEEP DIVE INTO RECOVERED SAMPLES:")
    for file_path in sample_files:
        filename = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            content = f.read()
        val = validator.validate(content)
        if val.get("recovery_notes"):
            print(f"\n[Recovered: {filename}]")
            for note in val["recovery_notes"]:
                print(f"  - {note}")

if __name__ == "__main__":
    verify_all_samples()
