import json
import pandas as pd

def get_severity(license_name):
    if not license_name:
        return "no"
    license_name = license_name.lower()
    if "gpl" in license_name and "lgpl" not in license_name:
        return "high"
    elif "lgpl" in license_name:
        return "medium"
    elif "apache" in license_name or "mit" in license_name or "bsd" in license_name:
        return "no"
    else:
        return "no"

def extract_from_syft_json(syft_json_path="syft-sbom.json", output_excel_path="compliance-report.xlsx"):
    with open(syft_json_path, 'r', encoding='utf-8') as file:
        data = json.load(file)

    components = []
    for artifact in data.get("artifacts", []):
        name = artifact.get("name", "unknown")
        version = artifact.get("version", "unknown")
        license_info = artifact.get("licenses", [])
        license_concluded = license_info[0]["value"] if license_info else "NOASSERTION"
        purl = artifact.get("purl", "unknown")
        severity = get_severity(license_concluded)

        components.append({
            "Component": name,
            "Version": version,
            "License": license_concluded,
            "License URL": purl,
            "Severity": severity
        })

    df = pd.DataFrame(components)
    df.to_excel(output_excel_path, index=False)

if __name__ == "__main__":
    extract_from_syft_json()
