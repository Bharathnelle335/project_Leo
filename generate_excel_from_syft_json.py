import json
import pandas as pd
import sys

# Read SPDX JSON file from Syft
with open('syft-sbom.spdx.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

packages = data.get("packages", [])

rows = []
for pkg in packages:
    name = pkg.get("name", "unknown")
    version = pkg.get("versionInfo", "unknown")
    license = pkg.get("licenseConcluded", "NOASSERTION")
    license_url = None

    # Try to find license URL
    for extRef in pkg.get("externalRefs", []):
        if extRef.get("referenceType") == "purl" and "github.com" in extRef.get("referenceLocator", ""):
            license_url = extRef.get("referenceLocator")
            break

    # Classify severity
    if "GPL" in license and "LGPL" not in license:
        severity = "high"
    elif "LGPL" in license or "MPL" in license:
        severity = "medium"
    elif license == "NOASSERTION":
        severity = "no"
    else:
        severity = "no"

    rows.append({
        "Component": name,
        "Version": version,
        "License": license,
        "License URL": license_url or "unknown",
        "Severity": severity
    })

# Write to Excel
df = pd.DataFrame(rows)
df.to_excel("compliance-report.xlsx", index=False)
print("✅ compliance-report.xlsx generated.")
