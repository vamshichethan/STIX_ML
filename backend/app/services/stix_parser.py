import json
import logging
from lxml import etree

logger = logging.getLogger(__name__)

def detect_version(content: bytes, filename: str) -> str:
    """ Detects if the file is STIX 1.x (XML) or 2.x (JSON) and attempts to find exact versions. """
    content_stripped = content.strip()
    
    if filename.endswith(".json") or content_stripped.startswith(b"{"):
        try:
            data = json.loads(content_stripped)
            # Check for STIX 2.1 specific indicators
            if "spec_version" in data:
                return data["spec_version"]
            # Fallback deduction
            if data.get("type") == "bundle":
                for obj in data.get("objects", []):
                    if obj.get("spec_version"):
                        return obj["spec_version"]
            return "2.x"  # Default 2.x
        except json.JSONDecodeError:
            return "2.x"
            
    elif filename.endswith(".xml") or content_stripped.startswith(b"<"):
        try:
            # Only parsing the start to avoid full load for detection
            parser = etree.XMLPullParser(events=('start',))
            parser.feed(content_stripped)
            for event, elem in parser.read_events():
                # Check STIX 1 namespace and version attribute
                if 'version' in elem.attrib:
                    return f"1.{elem.attrib['version'].split('.')[1]}" if '.' in elem.attrib['version'] else elem.attrib['version']
                break # Only checking root
            return "1.x"
        except etree.XMLSyntaxError:
            return "1.x"
            
    return "unknown"

def parse_stix(content: bytes, filename: str) -> dict:
    """ Extensively normalize STIX content to standard dictionary format. """
    version = detect_version(content, filename)
    
    if version.startswith("2."):
        try:
            data = json.loads(content)
            if data.get("type", "").lower() != "bundle":
                return {"valid": False, "errors": ["Missing 'type': 'bundle' for STIX 2.x"]}
            
            # Ensure "objects" exists
            if "objects" not in data:
                data["objects"] = []
                
            return {"valid": True, "version": version, "data": data}
        except Exception as e:
            return {"valid": False, "errors": [str(e)]}
            
    elif version.startswith("1."):
        try:
            parser = etree.XMLParser(recover=True)
            root = etree.fromstring(content, parser=parser)
            
            # Extract common elements and map to pseudo-STIX2 JSON objects
            data = {"id": root.attrib.get('id', 'unknown'), "type": "bundle", "objects": []}
            
            # Helper to strip namespace
            def _strip_ns(tag):
                return tag.split('}')[-1] if '}' in tag else tag

            for elem in root.iter():
                tag_name = _strip_ns(elem.tag).lower()
                # If it's a major STIX 1 object type
                if tag_name in ['observable', 'indicator', 'ttp', 'incident', 'campaign', 'threat_actor', 'course_of_action']:
                    obj_id = elem.attrib.get('id', f"{tag_name}--unknown")
                    
                    title_nodes = elem.xpath('.//*[local-name()="Title"]')
                    title = title_nodes[0].text if title_nodes and title_nodes[0].text else "Unknown Title"
                    
                    desc_nodes = elem.xpath('.//*[local-name()="Description"]')
                    description = desc_nodes[0].text if desc_nodes and desc_nodes[0].text else ""
                    
                    # Simplified conversion for ML pipeline consumption
                    stix_obj = {
                        "type": tag_name,
                        "id": obj_id,
                        "title": title,
                        "description": description
                    }
                    data["objects"].append(stix_obj)
                    
            return {"valid": True, "version": version, "data": data}
        except Exception as e:
            logger.exception("Failed to parse STIX 1.x XML")
            return {"valid": False, "errors": [str(e)]}
            
    return {"valid": False, "errors": ["Unknown or unsupported format"]}
