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

# Prepare SCANOSS DataFrame
scanoss_rows = []
scanoss_license_map = {}

# Iterate through each file and its match list
for file_matches in scanoss_data.values():
    for match in file_matches:
        component = match.get('component') or ""
        version = match.get('version') or ""
        vendor = match.get('vendor') or ""
        repo_url = match.get('url') or ""
        licenses = match.get('licenses', [])

        license_names = ", ".join([lic.get('name', '') for lic in licenses if 'name' in lic])
        license_urls = ", ".join([lic.get('url', '') for lic in licenses if 'url' in lic])

        if component:
            scanoss_rows.append({
                'Component Name': component,
                'Version': version,
                'Vendor': vendor,
                'Repo URL': repo_url,
                'License Names': license_names,
                'License URLs': license_urls
            })
            if license_names:
                scanoss_license_map[component] = license_names

scanoss_df = pd.DataFrame(scanoss_rows)

# Save Syft-only Compliance Report
syft_only_df = syft_df[['Component Name', 'Version', 'Syft License']]
syft_only_df.to_excel('syft-compliance-report.xlsx', index=False)

# Save SCANOSS-only Compliance Report
if not scanoss_df.empty:
    scanoss_df.to_excel('scanoss-compliance-report.xlsx', index=False)
else:
    pd.DataFrame(columns=['Component Name', 'Version', 'Vendor', 'Repo URL', 'License Names', 'License URLs']).to_excel('scanoss-compliance-report.xlsx', index=False)

# Now merge Syft and SCANOSS properly
# Syft: Component Name, Version, Syft License
# SCANOSS: Component Name, License Names

# Prepare SCANOSS license mapping DataFrame
scanoss_license_df = scanoss_df[['Component Name', 'License Names']].rename(columns={'License Names': 'SCANOSS License'})

# Merge both (outer join to capture everything)
merged_df = pd.merge(syft_only_df, scanoss_license_df, on='Component Name', how='outer')

# Fill missing versions
merged_df['Version'] = merged_df['Version'].fillna('')

# Decide Final License
final_license = []
for _, row in merged_df.iterrows():
    syft_license = (row.get('Syft License') or '').strip()
    scanoss_license = (row.get('SCANOSS License') or '').strip()
    if syft_license and syft_license.upper() not in ('NOASSERTION', 'UNKNOWN'):
        final_license.append(syft_license)
    elif scanoss_license:
        final_license.append(scanoss_license)
    else:
        final_license.append('NOASSERTION')

merged_df['Final License'] = final_license

# Final Output
final_df = merged_df[['Component Name', 'Version', 'Final License']]
final_df.to_excel('compliance-report.xlsx', index=False)

print("✅ All compliance Excel reports generated successfully: syft-compliance-report.xlsx, scanoss-compliance-report.xlsx, compliance-report.xlsx")
