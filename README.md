📢 Main Release - OSS Compliance & SBOM Automation (Syft + SCANOSS)
Summary
This project provides a fully automated solution for OSS Compliance and SBOM (Software Bill of Materials) generation using Syft, SCANOSS, and GitHub Actions.
It enables scanning source code, generating SBOMs, detecting open-source licenses, and compiling a final compliance report automatically.

🚀 Key Features
Automatic OSS License Detection

Combines license detection from Syft and SCANOSS.

SBOM (Software Bill of Materials) Generation

Uses Syft to produce detailed SPDX-compliant SBOM reports.

Compliance Report Creation

Merges detected licenses into a final Excel report for easy review.

Fully Automated GitHub Actions Workflow

Triggered on push to main branch or manually via Workflow Dispatch.

Multi-Tool Integration

Syft CLI, SCANOSS CLI, and Python scripts combined into one seamless process.

Safe Error Handling

Ensures fallback when SCANOSS results are missing or incomplete.

📦 Outputs Generated
compliance-report.xlsx — Final compliance report mapping components to licenses.

syft-sbom.spdx.json — Full SBOM generated using Syft.

scanoss-results.json — Raw SCANOSS scan results for traceability.

All outputs are available as downloadable artifacts from GitHub Actions.

🛠 Tools Used
Syft (by Anchore)

SCANOSS (Open Source Software Scanning)

GitHub Actions (CI/CD Automation)

Python (pandas, openpyxl)

📋 How It Works
Source code checked out from GitHub.

Maven project built to pull dependencies.

SCANOSS scans source folder (demo/) for license detection.

Syft generates an SBOM from the project source.

Python script merges Syft and SCANOSS results.

Compliance Excel report generated and uploaded.

🧠 Future Enhancements (Optional)
Enrich License Homepage URLs using GitHub APIs.

Add Risk/Severity scoring based on license types.

Generate reports in additional formats (e.g., PDF, HTML).

