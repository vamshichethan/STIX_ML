import json
import logging
from lxml import etree

logger = logging.getLogger(__name__)

def detect_version(content: bytes, filename: str) -> str:
    """ Detects STIX version or returns 'fallback' for non-STIX data. """
    content_stripped = content.strip()
    
    if filename.endswith(".json") or content_stripped.startswith(b"{"):
        try:
            data = json.loads(content_stripped)
            if "spec_version" in data: return data["spec_version"]
            if data.get("type") == "bundle": return "2.x"
            return "2.x-inferred" 
        except:
            return "json-fallback"
            
    elif filename.endswith(".xml") or content_stripped.startswith(b"<"):
        return "1.x-check"
            
    return "text-fallback"

def parse_stix(content: bytes, filename: str) -> dict:
    """ Normalize STIX content, with robust fallback for non-STIX data. """
    version = detect_version(content, filename)
    
    # 1. Standard STIX 2.x JSON
    if version.startswith("2.") or version == "json-fallback":
        try:
            data = json.loads(content)
            if data.get("type") == "bundle" and "objects" in data:
                return {"valid": True, "version": version, "data": data}
            
            # Wrap random JSON into a Pseudo-STIX Bundle
            pseudo_bundle = {
                "type": "bundle",
                "id": f"bundle--inferred-{hash(filename)}",
                "objects": [
                    {
                        "type": "observed-data",
                        "id": "observed-data--random",
                        "description": f"Non-STIX JSON Data detected: {str(data)[:200]}...",
                        "raw_json": data
                    }
                ]
            }
            return {"valid": True, "version": "inferred-2.1", "data": pseudo_bundle, "warning": "Non-STIX data wrapped for analysis"}
        except:
            # Continue to text fallback if JSON load fails
            pass

    # 2. Standard STIX 1.x XML
    if version.startswith("1.") or version == "1.x-check":
        try:
            parser = etree.XMLParser(recover=True)
            root = etree.fromstring(content, parser=parser)
            data = {"id": root.attrib.get('id', 'unknown'), "type": "bundle", "objects": []}
            
            # ... (keep existing 1.x logic if possible, or simplified version)
            found_objects = False
            for elem in root.iter():
                tag = elem.tag.split('}')[-1].lower()
                if tag in ['observable', 'indicator', 'incident']:
                    data["objects"].append({"type": tag, "description": elem.text or ""})
                    found_objects = True
            
            if found_objects:
                return {"valid": True, "version": "1.x", "data": data}
        except:
            pass

    # 3. Ultimate Fallback: Treat as plain text / random noise
    try:
        text_content = content.decode('utf-8', errors='ignore')
        pseudo_bundle = {
            "type": "bundle",
            "id": "bundle--text-fallback",
            "objects": [
                {
                    "type": "note",
                    "id": "note--random",
                    "abstract": "Inferred intelligence from raw signal",
                    "content": text_content[:500] # Pass snippet to ML
                }
            ]
        }
        return {"valid": True, "version": "plaintext-inferred", "data": pseudo_bundle}
    except:
        return {"valid": False, "errors": ["Failed to interpret data even in fallback mode"]}
