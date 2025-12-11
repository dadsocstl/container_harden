# STL Cyber - Container Security Scanner 🛡️

**DoD Edition with CFIUS Compliance, OSS License Validation, and NIST 800-53 Mapping**

## Features

✅ **Comprehensive Security Scanning**
- Vulnerability detection (CRITICAL/HIGH/MEDIUM/LOW)
- Secret exposure detection
- Misconfiguration analysis
- License compliance validation

✅ **DoD Compliance**
- CFIUS foreign ownership analysis
- OSI license validation per DoD CIO Memo (Oct 2009)
- NIST SP 800-53 Rev5 mapping
- Executive Order 13873 compliance
- NDAA Section 889 checks

✅ **Threat Intelligence**
- Cross-reference with NVD, CERT/CC, Exploit-DB, Talos Intelligence
- Direct links to vulnerability databases
- Exploit availability checks

✅ **Enterprise Reporting**
- Unified compliance CSV for tracking
- HTML reports with visual styling
- JSON/TXT for automation
- SBOM (CycloneDX)
- MITRE SAF HDF (eMASS-ready)
- OpenSCAP XCCDF
- DISA STIG Viewer CKL

## Quick Start 🚀

### Pull the Image

```bash
docker pull stlcyber/container-scanner:latest
```

### Run a Scan

```bash
# Basic scan
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/results:/results \
  stlcyber/container-scanner:latest ubuntu:20.04

# Scan with custom output directory
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/results:/results \
  stlcyber/container-scanner:latest myapp:latest /results/myapp-scan
```

### Windows (PowerShell)

```powershell
docker run --rm `
  -v /var/run/docker.sock:/var/run/docker.sock `
  -v ${PWD}/results:/results `
  stlcyber/container-scanner:latest ubuntu:20.04
```

## Output Reports 📊

After scanning, you'll find these reports in your output directory:

### 📊 Unified Compliance Report
- **CSV**: `*_unified_compliance_*.csv` - Risk classification (CRITICAL/HIGH/MEDIUM/LOW), country of origin, license status
- **TXT**: Detailed analysis with regulatory references
- **JSON**: Machine-readable for automation
- **HTML**: Visual report with styling

### 🌍 Foreign Ownership Analysis
- **TXT**: CFIUS compliance report with country breakdown
- **JSON**: Structured data for supply chain risk management
- Identifies packages from China, Russia, Iran, North Korea 🇨🇳🇷🇺🇮🇷🇰🇵
- Maps to DoD supply chain risk frameworks

### 🛡️ Vulnerability Reports
- **HTML**: Color-coded severity tables
- **TBL**: Text-based tables with Unicode
- **JSON**: Full vulnerability details with CVE IDs

### 📜 License Compliance
- **HTML**: License tables with package mapping
- **JSON**: OSI validation results
- **TXT**: DoD approval required packages

### 🔍 Threat Intelligence
- **HTML**: Clickable links to NVD, CERT/CC, Exploit-DB, Talos
- **JSON**: Cross-reference data for automation

### 📋 SBOM & Compliance
- **CycloneDX**: Software Bill of Materials
- **HDF**: MITRE SAF format (eMASS upload ready)
- **XCCDF**: OpenSCAP compliance
- **CKL**: DISA STIG Viewer format

## Risk Classification ⚠️

| Risk Level | Criteria | Action Required |
|-----------|----------|-----------------|
| **CRITICAL** 🔴 | Foreign adversary nation (CN/RU/IR/KP) + Non-OSI license | Immediate review, seek alternatives |
| **HIGH** 🟠 | Foreign origin (any non-US) | Supply chain risk assessment |
| **MEDIUM** 🟡 | Non-OSI license | DoD approval required |
| **LOW** 🟢 | US origin + OSI approved | Standard deployment |

## Architecture 🏗️

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Container                         │
├─────────────────────────────────────────────────────────────┤
│  Ubuntu 22.04 Base                                         │
│  • Trivy Security Scanner                                   │
│  • Python 3 + jq                                           │
│  • Docker client (uses host socket)                        │
├─────────────────────────────────────────────────────────────┤
│  Scripts & Databases                                        │
│  • improved.sh (main orchestrator)                         │
│  • OSI license database (188 licenses)                     │
│  • Country origin database (100+ packages)                 │
│  • Python converters (TBL→HTML, NIST mapping)              │
└─────────────────────────────────────────────────────────────┘
         ↓                                    ↓
   /var/run/docker.sock           /results (output)
   (host Docker access)           (scan results)
```

## Requirements 📋

- Docker installed on host 🐳
- Docker socket access (`/var/run/docker.sock`)
- 2GB RAM minimum 💾
- Internet connection (for pulling images and databases) 🌐

## Environment Variables ⚙️

```bash
# Optional: Cache directory for Trivy
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/results:/results \
  -v $(pwd)/trivy-cache:/app/.trivy-cache \
  stlcyber/container-scanner:latest ubuntu:20.04
```

## Use Cases 🔧

### 1. CI/CD Pipeline Integration

```yaml
# GitLab CI example
container_scan:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker pull stlcyber/container-scanner:latest
    - docker run --rm 
        -v /var/run/docker.sock:/var/run/docker.sock 
        -v $(pwd)/results:/results 
        stlcyber/container-scanner:latest $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  artifacts:
    paths:
      - results/
    expire_in: 30 days
```

### 2. Pre-Deployment Validation

```bash
#!/bin/bash
# pre-deploy.sh
IMAGE="$1"
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/compliance-reports:/results \
  stlcyber/container-scanner:latest "$IMAGE"

# Check for CRITICAL findings
if grep -q "CRITICAL" results/*/reports/*_unified_compliance_*.csv; then
  echo "CRITICAL findings detected - deployment blocked ❌"
  exit 1
fi
```

### 3. Supply Chain Audit

```bash
# Scan entire registry
for image in $(docker images --format "{{.Repository}}:{{.Tag}}"); do
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v $(pwd)/audit-results:/results \
    stlcyber/container-scanner:latest "$image" "/results/${image//\//_}"
done

# Generate consolidated report
cat audit-results/*/reports/*_unified_compliance_*.csv > supply_chain_audit.csv
```

## Building from Source 🛠️

```bash
# Clone repository
git clone https://github.com/dadsocstl/container_harden.git
cd container_harden

# Option 1: Standard Ubuntu-based image (includes all tools)
docker build -t stlcyber/container-scanner:latest .

# Option 2: DoD-compliant RHEL UBI8 image (includes all tools)
docker build -f DoDEnv_Dockerfile -t stlcyber/container-scanner:dod .

# Option 3: Lightweight DoD image (assumes tools pre-installed)
docker build -f Lightweight_DoDEnv_Dockerfile -t stlcyber/container-scanner:lightweight .

# Test any version
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/results:/results \
  stlcyber/container-scanner:latest ubuntu:20.04
```

### Pre-installed Tools Support

The scanner automatically detects and uses pre-installed tools regardless of version:
- **Trivy**: Any version for vulnerability scanning
- **Docker/Podman**: Any version for container operations  
- **MITRE SAF CLI**: Any version for compliance reporting

If tools are missing, the script will attempt to install them automatically.

## Compliance References 📚

- **CFIUS**: Committee on Foreign Investment in the United States
- **EO 13873**: Securing the Information and Communications Technology and Services Supply Chain
- **NDAA Section 889**: Prohibition on Certain Telecommunications Equipment
- **DoD CIO Memo**: Clarifying Guidance Regarding Open Source Software (Oct 16, 2009)
- **NIST SP 800-161**: Cybersecurity Supply Chain Risk Management
- **NIST SP 800-53 Rev5**: Security and Privacy Controls

## Support 🆘

For issues, feature requests, or questions:
- GitHub Issues: https://github.com/dadsocstl/container_harden/issues
- Documentation: See `UNIFIED_COMPLIANCE_CSV_REFERENCE.md` for CSV format details

## License 📄

MIT License - See LICENSE file for details

## Credits 🙏

Developed by: 3290178  
Organization: DoD Cyber Security  
Version: 2025.1  
Last Updated: December 2025

- [GitHub Actions](https://github.com/aquasecurity/trivy-action)
- [Kubernetes operator](https://github.com/aquasecurity/trivy-operator)
- [VS Code plugin](https://github.com/aquasecurity/trivy-vscode-extension)
- See [Ecosystem] for more

### Canary builds
There are canary builds ([Docker Hub](https://hub.docker.com/r/aquasec/trivy/tags?page=1&name=canary), [GitHub](https://github.com/aquasecurity/trivy/pkgs/container/trivy/75776514?tag=canary), [ECR](https://gallery.ecr.aws/aquasecurity/trivy#canary) images and [binaries](https://github.com/aquasecurity/trivy/actions/workflows/canary.yaml)) as generated every push to main branch.

Please be aware: canary builds might have critical bugs, it's not recommended for use in production.

### General usage

```bash
trivy <target> [--scanners <scanner1,scanner2>] <subject>
```

Examples:

```bash
trivy image python:3.4-alpine
```

<details>
<summary>Result</summary>

https://user-images.githubusercontent.com/1161307/171013513-95f18734-233d-45d3-aaf5-d6aec687db0e.mov

</details>

```bash
trivy fs --scanners vuln,secret,misconfig myproject/
```

<details>
<summary>Result</summary>

https://user-images.githubusercontent.com/1161307/171013917-b1f37810-f434-465c-b01a-22de036bd9b3.mov

</details>

```bash
trivy k8s --report summary cluster
```

<details>
<summary>Result</summary>

![k8s summary](docs/imgs/trivy-k8s.png)

</details>

## FAQ

### How to pronounce the name "Trivy"?

`tri` is pronounced like **tri**gger, `vy` is pronounced like en**vy**.

## Want more? Check out Aqua

If you liked Trivy, you will love Aqua which builds on top of Trivy to provide even more enhanced capabilities for a complete security management offering.  
You can find a high level comparison table specific to Trivy users [here](https://github.com/aquasecurity/resources/blob/main/trivy-aqua.md).  
In addition check out the <https://aquasec.com> website for more information about our products and services.
If you'd like to contact Aqua or request a demo, please use this form: <https://www.aquasec.com/demo>

## Community

Trivy is an [Aqua Security][aquasec] open source project.  
Learn about our open source work and portfolio [here][oss].  
Contact us about any matter by opening a GitHub Discussion [here][discussions]
Join our [Slack community][slack] to stay up to date with community efforts.

Please ensure to abide by our [Code of Conduct][code-of-conduct] during all interactions.

[test]: https://github.com/aquasecurity/trivy/actions/workflows/test.yaml
[test-img]: https://github.com/aquasecurity/trivy/actions/workflows/test.yaml/badge.svg
[go-report]: https://goreportcard.com/report/github.com/aquasecurity/trivy
[go-report-img]: https://goreportcard.com/badge/github.com/aquasecurity/trivy
[release]: https://github.com/aquasecurity/trivy/releases
[release-img]: https://img.shields.io/github/release/aquasecurity/trivy.svg?logo=github
[github-downloads-img]: https://img.shields.io/github/downloads/aquasecurity/trivy/total?logo=github
[docker-pulls]: https://img.shields.io/docker/pulls/aquasec/trivy?logo=docker&label=docker%20pulls%20%2F%20trivy
[license]: https://github.com/aquasecurity/trivy/blob/main/LICENSE
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[homepage]: https://trivy.dev
[docs]: https://aquasecurity.github.io/trivy
[pronunciation]: #how-to-pronounce-the-name-trivy
[slack]: https://slack.aquasec.com
[code-of-conduct]: https://github.com/aquasecurity/community/blob/main/CODE_OF_CONDUCT.md

[Installation]:https://aquasecurity.github.io/trivy/latest/getting-started/installation/
[Ecosystem]: https://aquasecurity.github.io/trivy/latest/ecosystem/
[Scanning Coverage]: https://aquasecurity.github.io/trivy/latest/docs/coverage/

[alpine]: https://ariadne.space/2021/06/08/the-vulnerability-remediation-lifecycle-of-alpine-containers/
[rego]: https://www.openpolicyagent.org/docs/latest/#rego
[sigstore]: https://www.sigstore.dev/

[aquasec]: https://aquasec.com
[oss]: https://www.aquasec.com/products/open-source-projects/
[discussions]: https://github.com/aquasecurity/trivy/discussions
