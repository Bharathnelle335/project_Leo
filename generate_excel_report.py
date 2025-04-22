import pandas as pd
import json
import sys

def load_scanoss(scanoss_path):
    try:
        with open(scanoss_path) as f:
            return json.load(f)
    except:
        return []

def load_syft(syft_path):
    with open(syft_path) as f:
        return json.load(f)

def severity_from_license(license_name):
    if 'GPL' in license_name and 'LGPL' not in license_name:
        return 'high'
    elif 'LGPL' in license_name:
        return 'medium'
    elif license_name == 'unknown' or license_name.strip() == '':
        return 'unknown'
    else:
        return 'no'

def generate_report(scanoss_json, syft_json, output_excel):
    syft = load_syft(syft_json)

    records = []
    for pkg in syft.get("packages", []):
        name = pkg.get("name", "unknown")
        version = pkg.get("versionInfo", "unknown")
        license = pkg.get("licenseConcluded", "unknown")
        homepage = pkg.get("homepage", "unknown")

        records.append({
            "Component": name,
            "Version": version,
            "License": license,
            "License URL": homepage,
            "Severity": severity_from_license(license)
        })

    df = pd.DataFrame(records)
    df.to_excel(output_excel, index=False)

if __name__ == "__main__":
    # For GitHub Actions: fixed filenames
    generate_report("scanoss-results.json", "syft-sbom.spdx.json", "compliance-report.xlsx")
