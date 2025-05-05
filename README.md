# Source Code Compliance Scanner (SCANOSS + Syft)

This project scans a source code repository using SCANOSS and Syft, and generates:
- SPDX JSON report
- Combined Excel license report
![source-code-scan-scanoss-syft Flow Image](https://github.com/user-attachments/assets/7bfdd5e6-a1b0-42b4-b1e0-da14652146f7)

## Tools Used
- SCANOSS CLI
- Syft
- Python (for merging + Excel output)

## Output
- `scanoss-results.json`
- `syft-sbom.spdx.json`
- `combined_licenses.xlsx`

## How to Use
Run the GitHub Actions workflow with a target Git repository.
Reports will be uploaded as artifacts.

## License
This project is licensed under the Apache License 2.0.  
See the [LICENSE](./LICENSE) file for details.
