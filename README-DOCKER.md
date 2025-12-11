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

## Quick Start

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

## Output Reports

After scanning, you'll find these reports in your output directory:

### 📊 Unified Compliance Report
- **CSV**: `*_unified_compliance_*.csv` - Risk classification (CRITICAL/HIGH/MEDIUM/LOW), country of origin, license status
- **TXT**: Detailed analysis with regulatory references
- **JSON**: Machine-readable for automation
- **HTML**: Visual report with styling

### 🌍 Foreign Ownership Analysis
- **TXT**: CFIUS compliance report with country breakdown
- **JSON**: Structured data for supply chain risk management
- Identifies packages from China, Russia, Iran, North Korea
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

## Risk Classification

| Risk Level | Criteria | Action Required |
|-----------|----------|-----------------|
| **CRITICAL** | Foreign adversary nation (CN/RU/IR/KP) + Non-OSI license | Immediate review, seek alternatives |
| **HIGH** | Foreign origin (any non-US) | Supply chain risk assessment |
| **MEDIUM** | Non-OSI license | DoD approval required |
| **LOW** | US origin + OSI approved | Standard deployment |

## Architecture

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

## Requirements

- Docker installed on host
- Docker socket access (`/var/run/docker.sock`)
- 2GB RAM minimum
- Internet connection (for pulling images and databases)

## Environment Variables

```bash
# Optional: Cache directory for Trivy
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/results:/results \
  -v $(pwd)/trivy-cache:/app/.trivy-cache \
  stlcyber/container-scanner:latest ubuntu:20.04
```

## Use Cases

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
  echo "CRITICAL findings detected - deployment blocked"
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

## Building from Source

```bash
# Clone repository
git clone https://github.com/dod-cyber/container-hardening.git
cd container-hardening

# Build image
docker build -t stlcyber/container-scanner:latest .

# Test
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/results:/results \
  stlcyber/container-scanner:latest ubuntu:20.04
```

## Compliance References

- **CFIUS**: Committee on Foreign Investment in the United States
- **EO 13873**: Securing the Information and Communications Technology and Services Supply Chain
- **NDAA Section 889**: Prohibition on Certain Telecommunications Equipment
- **DoD CIO Memo**: Clarifying Guidance Regarding Open Source Software (Oct 16, 2009)
- **NIST SP 800-161**: Cybersecurity Supply Chain Risk Management
- **NIST SP 800-53 Rev5**: Security and Privacy Controls

## Support

For issues, feature requests, or questions:
- GitHub Issues: https://github.com/dod-cyber/container-hardening/issues
- Documentation: See `UNIFIED_COMPLIANCE_CSV_REFERENCE.md` for CSV format details

## License

MIT License - See LICENSE file for details

## Credits

Developed by: 3290178  
Organization: DoD Cyber Security  
Version: 2025.1  
Last Updated: December 2025
