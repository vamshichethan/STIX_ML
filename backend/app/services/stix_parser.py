import json
import logging
from typing import Dict, Any
from app.services.stix_validator import STIXValidator

logger = logging.getLogger(__name__)

def parse_stix(content: bytes, filename: str) -> Dict[str, Any]:
    """
    Standardizes and validates STIX content using the advanced STIXValidator engine.
    Supports auto-correction and structural recovery.
    """
    validator = STIXValidator()
    
    # 1. Run rigorous validation and recovery
    result = validator.validate(content)
    
    # 2. Extract cleaned/recovered data
    if result["overall_status"] != "INVALID" or result.get("auto_corrected_data"):
        data = result.get("auto_corrected_data")
        # If validator failed to provide full data but marked as valid (XML case), fall back to raw content
        if not data:
            try:
                if content.strip().startswith(b"{"):
                    data = json.loads(content)
                else:
                    data = {"id": filename, "type": "bundle", "objects": []}
            except:
                data = {"id": filename, "type": "bundle", "objects": []}

        return {
            "valid": True,
            "version": result.get("version", "Unknown"),
            "data": data,
            "validation": result
        }
    
    # 3. Handle failure
    return {
        "valid": False,
        "errors": [err["issue"] for err in result.get("invalid_fields", [])],
        "validation": result
    }
