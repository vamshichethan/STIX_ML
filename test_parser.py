import os
from backend.app.services.stix_parser import parse_stix

def main():
    # Test STIX 2
    with open("sample_stix.json", "rb") as f:
        content = f.read()
    
    res = parse_stix(content, "sample_stix.json")
    print("STIX 2 parse result:")
    print(res)

    # Test STIX 1
    with open("test_stix_1.xml", "rb") as f:
        content_xml = f.read()
    res_xml = parse_stix(content_xml, "test_stix_1.xml")
    print("\nSTIX 1 parse result:")
    print(res_xml)

if __name__ == "__main__":
    main()
