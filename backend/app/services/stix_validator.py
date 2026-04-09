import json
import re
import logging
import copy
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from app.services.stix_version_detector import STIXVersionDetector

logger = logging.getLogger(__name__)

class STIXValidator:
    """
    Analyzes STIX objects, classifies fields, assigns validation scores, 
    provides suggestions, and performs partial recovery.
    """

    def __init__(self):
        self.detector = STIXVersionDetector()
        self.uuid_regex = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        
        self.schemas = {
            "2.0": {
                "required": ["type", "id"],
                "object_required": ["type", "id", "created", "modified"]
            },
            "2.1": {
                "required": ["type", "id", "spec_version"],
                "object_required": ["type", "id", "created", "modified"]
            },
            "1.x": {
                "required": ["id"],
                "object_required": ["id"]
            }
        }

    def _is_valid_timestamp(self, ts_str: str) -> bool:
        if not isinstance(ts_str, str): return False
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f+00:00"):
            try:
                datetime.strptime(ts_str, fmt)
                return True
            except: continue
        return False

    def _attempt_timestamp_recovery(self, ts_str: str) -> Optional[str]:
        """Try to normalize different timestamp formats to ISO 8601."""
        if not isinstance(ts_str, str): return None
        # Try a more forgiving parser if available, or common variants
        formats = ["%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d", "%d-%m-%Y"]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str, fmt)
                return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            except: continue
        return None

    def _is_valid_id(self, id_str: str, expected_type: Optional[str] = None) -> bool:
        if not isinstance(id_str, str): return False
        parts = id_str.split("--")
        if len(parts) != 2: return False
        obj_type, uuid_part = parts
        if expected_type and obj_type != expected_type: return False
        return bool(self.uuid_regex.match(uuid_part))

    def _calculate_score(self, missing: int, invalid: int, warnings: int) -> int:
        score = 100 - (missing * 20) - (invalid * 15) - (warnings * 2)
        return max(0, score)

    def validate_object(self, obj: Dict[str, Any], version: str) -> Dict[str, Any]:
        """Validate a single STIX object or bundle, providing scores, suggestions, and recovery."""
        valid_fields = []
        missing_fields = []
        invalid_fields = []
        suggestions = {}
        warnings = []
        
        recovered_data = copy.deepcopy(obj)
        auto_corrected_fields = []
        
        schema = self.schemas.get(version, self.schemas["2.0"])
        is_bundle = obj.get("type") == "bundle"
        
        # 0. Pre-processing: Field Name Normalization (Recovery)
        original_keys = list(obj.keys())
        for key in original_keys:
            if key.lower() != key and key.lower() in ["type", "id", "created", "modified", "spec_version", "objects"]:
                recovered_data[key.lower()] = recovered_data.pop(key)
                auto_corrected_fields.append(f"Field name '{key}' normalized to '{key.lower()}'")
        
        # 1. Handle bundle objects recursively
        if is_bundle and "objects" in recovered_data:
            new_objects = []
            for item in recovered_data["objects"]:
                if isinstance(item, dict):
                    # Recurse for nested objects
                    item_val = self.validate_object(item, version)
                    new_objects.append(item_val.get("auto_corrected_data") or item)
                    if item_val.get("recovery_notes"):
                        auto_corrected_fields.extend([f"Object {item.get('id','?')}: {n}" for n in item_val["recovery_notes"]])
                    # Merge status
                    if item_val["overall_status"] == "INVALID":
                        invalid_fields.append({"field": f"objects[{item.get('id','?')}]", "issue": "Contains invalid data"})
                else:
                    new_objects.append(item)
            recovered_data["objects"] = new_objects

        required = schema["required"] if is_bundle else schema["object_required"]
        
        # 2. Check Required Fields
        for req in required:
            if req not in recovered_data:
                missing_fields.append(req)

        # 3. Iterate and Classify
        for field, value in list(recovered_data.items()):
            if field == "objects" and is_bundle: continue # Already handled
            
            is_valid = True
            issue = None
            suggestion = None
            
            if field == "id":
                obj_type = recovered_data.get("type", "type")
                if not self._is_valid_id(value, obj_type):
                    is_valid = False
                    issue = f"Incorrect ID format for {obj_type}"
                    suggestion = f"ID should follow format: {obj_type}--<UUIDv4>"
                    # Attempt recovery if it's just a hex/uuid
                    if self.uuid_regex.match(str(value)) or re.match(r"^[0-9a-fA-F-]+$", str(value)):
                        recovered_data[field] = f"{obj_type}--{value}"
                        auto_corrected_fields.append(f"ID prepended with type '{obj_type}'")
                        is_valid = True
            
            elif field in ["created", "modified", "first_observed", "last_observed"]:
                if not self._is_valid_timestamp(value):
                    normalized = self._attempt_timestamp_recovery(value)
                    if normalized:
                        recovered_data[field] = normalized
                        auto_corrected_fields.append(f"Timestamp '{field}' normalized to ISO 8601")
                    else:
                        is_valid = False
                        issue = "Invalid ISO 8601 timestamp"
                        suggestion = "Use format YYYY-MM-DDTHH:MM:SS.sssZ"
            
            elif field == "type":
                if not isinstance(value, str) or value.lower() != value:
                    is_valid = False
                    issue = "Type should be a lowercase string"
                    suggestion = "Example: 'threat-actor' instead of 'ThreatActor'"

            if is_valid:
                valid_fields.append(field)
            else:
                invalid_fields.append({"field": field, "issue": issue, "suggestion": suggestion})

        # 4. Warnings for unexpected fields
        common_fields = {"type", "id", "created", "modified", "spec_version", "objects", "name", "description", "labels", "confidence"}
        for field in recovered_data.keys():
            if field not in common_fields and field not in required and field != "objects":
                warnings.append(f"Unexpected field: {field}")

        score = self._calculate_score(len(missing_fields), len(invalid_fields), len(warnings))
        
        if score == 100: status = "VALID"
        elif score > 60: status = "PARTIAL_VALID"
        else: status = "INVALID"

        return {
            "version": version,
            "score": score,
            "overall_status": status,
            "valid_fields": valid_fields,
            "missing_fields": missing_fields,
            "invalid_fields": invalid_fields,
            "warnings": warnings,
            "auto_corrected_data": recovered_data,
            "recovery_notes": list(set(auto_corrected_fields))
        }

    def validate(self, content: bytes) -> Dict[str, Any]:
        detection = self.detector.detect(content)
        version = detection["version"]
        
        if version == "unknown":
            return {"score": 0, "overall_status": "INVALID", "invalid_fields": [{"field": "format", "issue": "Unknown STIX format"}]}
            
        try:
            if detection["features_detected"][0] == "format:json" or b"{" in content:
                data = json.loads(content)
                if isinstance(data, dict):
                    return self.validate_object(data, version)
        except Exception as e:
            return {"score": 0, "overall_status": "INVALID", "invalid_fields": [{"field": "parsing", "issue": str(e)}]}

        return {"score": 0, "overall_status": "INVALID", "invalid_fields": [{"field": "process", "issue": "Generic failure"}]}
