import json
import pandas as pd
import sys

# Accept SPDX JSON path as argument
if len(sys.argv) < 2:
    print("Usage: python3 generate_excel_from_syft_json.py <syft-sbom.spdx.json>")
    sys.exit(1)

syft_sbom_path = sys.argv[1]

with open(syft_sbom_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

components = []
for item in data.get("packages", []):
    name = item.get("name", "unknown")
    version = item.get("versionInfo", "unknown")
    license_info = item.get("licenseConcluded", "NOASSERTION")
    license_url = "unknown"

    for ref in item.get("externalRefs", []):
        if any(domain in ref.get("referenceLocator", "") for domain in ["spdx", "github"]):
            license_url = ref.get("referenceLocator")
            break

    license_lower = license_info.lower()
    if "gpl" in license_lower and "lgpl" not in license_lower:
        severity = "high"
    elif "lgpl" in license_lower or "mpl" in license_lower:
        severity = "medium"
    elif license_info == "NOASSERTION":
        severity = "no"
    else:
        severity = "no"

    components.append({
        "Component": name,
        "Version": version,
        "License": license_info,
        "License URL": license_url,
        "Severity": severity
    })

# Export to Excel
df = pd.DataFrame(components)
df.to_excel("compliance-report.xlsx", index=False)
print("✅ compliance-report.xlsx generated successfully.")
