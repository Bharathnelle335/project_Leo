# Filename: generate_excel_merge_syft_scanoss.py

import json
import pandas as pd
import sys

# Read Syft SBOM JSON file
syft_file = sys.argv[1] if len(sys.argv) > 1 else "syft-sbom.spdx.json"
with open(syft_file, 'r', encoding='utf-8') as f:
    syft_data = json.load(f)

# Read SCANOSS results JSON file
scanoss_file = sys.argv[2] if len(sys.argv) > 2 else "scanoss-results.json"
with open(scanoss_file, 'r', encoding='utf-8') as f:
    scanoss_data = json.load(f)

# Prepare Syft DataFrame
syft_rows = []
for pkg in syft_data.get('packages', []):
    name = pkg.get('name')
    version = pkg.get('versionInfo')
    license_concluded = pkg.get('licenseConcluded')
    syft_rows.append({
        'Component Name': name,
        'Version': version,
        'Syft License': license_concluded
    })
syft_df = pd.DataFrame(syft_rows)

# Prepare SCANOSS License Mapping and DataFrame
scanoss_rows = []
scanoss_license_map = {}

for match in scanoss_data.get('matches', []):
    component = match.get('component')
    if not component:
        component = match.get('file', '').split('/')[-1]
    license_detected = match.get('licenses', [{}])[0].get('name') if match.get('licenses') else None
    if component and license_detected:
        scanoss_rows.append({
            'Component Name': component,
            'SCANOSS License': license_detected
        })
        scanoss_license_map[component] = license_detected

scanoss_df = pd.DataFrame(scanoss_rows)

# Save Syft-only Compliance Report
syft_only_df = syft_df[['Component Name', 'Version', 'Syft License']]
syft_only_df.to_excel('syft-compliance-report.xlsx', index=False)

# Save SCANOSS-only Compliance Report
if not scanoss_df.empty:
    scanoss_df.to_excel('scanoss-compliance-report.xlsx', index=False)
else:
    # create empty if scanoss not found
    pd.DataFrame(columns=['Component Name', 'SCANOSS License']).to_excel('scanoss-compliance-report.xlsx', index=False)

# Prepare Final Merged Compliance Report
final_license = []

for _, row in syft_df.iterrows():
    syft_license = (row['Syft License'] or '').strip()
    component_name = row['Component Name']
    scanoss_license = scanoss_license_map.get(component_name, '')

    if not syft_license or syft_license.upper() in ('NOASSERTION', 'UNKNOWN'):
        final_license.append(scanoss_license if scanoss_license else syft_license)
    else:
        final_license.append(syft_license)

syft_df['Final License'] = final_license

# Arrange final merged columns
final_df = syft_df[['Component Name', 'Version', 'Final License']]
final_df.to_excel('compliance-report.xlsx', index=False)

print("✅ All compliance Excel reports generated successfully: syft-compliance-report.xlsx, scanoss-compliance-report.xlsx, compliance-report.xlsx")
