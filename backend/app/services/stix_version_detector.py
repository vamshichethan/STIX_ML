import json
import hashlib
import logging
import os
import re
from typing import Dict, Any, List, Optional, Set
from lxml import etree

logger = logging.getLogger(__name__)

class STIXVersionDetector:
    """
    Identifies the STIX version (1.x, 2.0, 2.1) of an input file 
    using structural fingerprint hashing.
    
    Enhanced with robustness, learning capability, and security monitoring.
    """

    def __init__(self, storage_path: str = "/Users/vamshi/Desktop/STIX_ML/backend/app/services/fingerprints.json"):
        self.storage_path = storage_path
        self.known_fingerprints = self._load_fingerprints()
        self.anomaly_threshold_nesting = 10
        self.max_key_length = 256

    def _load_fingerprints(self) -> Dict[str, str]:
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load fingerprints: {e}")
        return {}

    def _save_fingerprint(self, fingerprint: str, version: str):
        self.known_fingerprints[fingerprint] = version
        try:
            with open(self.storage_path, "w") as f:
                json.dump(self.known_fingerprints, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save fingerprints: {e}")

    @staticmethod
    def normalize_json(data: Any) -> Any:
        if isinstance(data, dict):
            return {k: STIXVersionDetector.normalize_json(v) for k in sorted(data.keys())}
        if isinstance(data, list):
            return [STIXVersionDetector.normalize_json(i) for i in data]
        return data

    @staticmethod
    def generate_fingerprint(features: List[str]) -> str:
        canonical_features = "|".join(sorted(features))
        return hashlib.sha256(canonical_features.encode('utf-8')).hexdigest()

    def _detect_anomalies(self, data: Any, depth: int = 0) -> List[str]:
        anomalies = []
        if depth > self.anomaly_threshold_nesting:
            anomalies.append(f"Excessive nesting detected (depth: {depth})")
        
        if isinstance(data, dict):
            for k, v in data.items():
                if len(str(k)) > self.max_key_length:
                    anomalies.append(f"Suspiciously long key detected: {str(k)[:50]}...")
                # Check for common obfuscation patterns (e.g., base64 looking keys)
                if re.match(r"^[a-zA-Z0-9+/]{50,}=*$", str(k)):
                    anomalies.append(f"Potential encoded/obfuscated key: {str(k)[:20]}...")
                anomalies.extend(self._detect_anomalies(v, depth + 1))
        elif isinstance(data, list):
            for item in data:
                anomalies.extend(self._detect_anomalies(item, depth + 1))
        return list(set(anomalies))

    def detect(self, content: bytes) -> Dict[str, Any]:
        content_str = content.strip()
        features = []
        version = "unknown"
        confidence = 0.0
        reasons = []
        anomalies = []

        # 1. Try JSON Analysis
        try:
            if content_str.startswith(b"{") or content_str.startswith(b"["):
                data = json.loads(content_str)
                features.append("format:json")
                reasons.append("File contains valid JSON structure")
                anomalies.extend(self._detect_anomalies(data))

                if isinstance(data, dict):
                    for key in sorted(data.keys()):
                        if key not in ["id", "created", "modified", "revised"]:
                            features.append(f"top_key:{key}")
                    
                    spec_version = data.get("spec_version")
                    if spec_version:
                        features.append(f"spec_version:{spec_version}")
                        if spec_version == "2.1":
                            version, confidence = "2.1", 0.99
                        elif spec_version == "2.0":
                            version, confidence = "2.0", 0.99
                    
                    if "objects" in data and isinstance(data["objects"], list):
                        obj_types = set()
                        v21_specific_types = {"grouping", "location", "infrastructure", "incident", "note", "opinion"}
                        
                        for obj in data["objects"]:
                            if isinstance(obj, dict):
                                obj_type = obj.get("type", "unknown")
                                obj_types.add(obj_type)
                                
                                # Heuristic: Detect 2.1 based on specific object types
                                if obj_type in v21_specific_types:
                                    features.append(f"detected_2.1_object:{obj_type}")
                                    version, confidence = "2.1", max(confidence, 0.9)
                                    reasons.append(f"Identified STIX 2.1 specific object type: {obj_type}")
                                
                                if "spec_version" in obj:
                                    features.append(f"object_level_spec:{obj['spec_version']}")
                                    if obj["spec_version"] == "2.1":
                                        version, confidence = "2.1", max(confidence, 0.95)
                                    elif obj["spec_version"] == "2.0":
                                        version, confidence = "2.0", max(confidence, 0.95)
                        
                        for t in sorted(obj_types):
                            features.append(f"contains_object_type:{t}")
                        
                        if version == "unknown":
                            # If no markers found, default to 2.0 (most common for legacy bundles)
                            version, confidence = "2.0", 0.7
                            reasons.append("Inferred STIX 2.0 based on structural profile")

        except json.JSONDecodeError as e:
            reasons.append(f"JSON Decode Error: {str(e)[:50]}... Attempting partial recovery")
            # Robustness: Partial Regex Extraction
            if b'"spec_version":' in content_str:
                match = re.search(r'"spec_version"\s*:\s*"([^"]+)"', content_str.decode('utf-8', errors='ignore'))
                if match:
                    ver = match.group(1)
                    features.append(f"partial_spec_version:{ver}")
                    version, confidence = ver, 0.5
                    reasons.append(f"Found partial spec_version via regex: {ver}")

        # 2. Try XML Analysis
        if version == "unknown":
            try:
                parser = etree.XMLParser(recover=True, remove_blank_text=True)
                root = etree.fromstring(content, parser=parser)
                features.append("format:xml")
                
                tags = set()
                for elem in root.iter():
                    tags.add(elem.tag.split('}')[-1])
                for tag in sorted(tags): features.append(f"tag:{tag}")

                namespaces = root.nsmap
                for prefix, ns in namespaces.items():
                    if ns:
                        features.append(f"namespace:{ns}")
                        if "stix-1" in ns:
                            version, confidence = "1.x", 0.95
                
                if "STIX_Package" in root.tag or any("stix" in t.lower() for t in tags):
                    if version == "unknown": version, confidence = "1.x", 0.8
                
                xml_version = root.attrib.get("version")
                if xml_version and xml_version.startswith("1."):
                    version, confidence = "1.x", 0.99

            except Exception as e:
                logger.debug(f"XML parsing failed: {e}")

        fingerprint = self.generate_fingerprint(features)

        # 3. Learning / Matching Check
        if fingerprint in self.known_fingerprints:
            known_ver = self.known_fingerprints[fingerprint]
            reasons.append(f"Matched known structural fingerprint for version {known_ver}")
            version = known_ver
            confidence = max(confidence, 0.98)
        elif version != "unknown" and confidence > 0.9:
            # Learn this new fingerprint
            self._save_fingerprint(fingerprint, version)
            reasons.append("New structural variant learned")

        return {
            "version": version,
            "confidence": confidence,
            "features_detected": features,
            "reasons": reasons,
            "fingerprint_hash": fingerprint,
            "security_alerts": anomalies
        }
