#!/bin/bash
set -e

echo "================================================================"
echo "    STL Cyber - Container Security & Compliance Scanner"
echo "    DoD Edition with CFIUS + OSS License + NIST Mapping"
echo "================================================================"
echo ""

# Check if Docker socket is mounted
if [ ! -S /var/run/docker.sock ]; then
    echo "ERROR: Docker socket not mounted!"
    echo "Please run with: docker run -v /var/run/docker.sock:/var/run/docker.sock ..."
    exit 1
fi

# Check if output directory is mounted
if [ ! -d /results ]; then
    echo "WARNING: /results directory not mounted. Results will be lost when container stops."
    echo "Recommended: docker run -v \$(pwd)/results:/results ..."
    mkdir -p /results
fi

# If no arguments, show usage
if [ $# -eq 0 ]; then
    echo "USAGE:"
    echo "  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \\"
    echo "             -v \$(pwd)/results:/results \\"
    echo "             stl-cyber/container-scanner:latest <IMAGE_NAME> [OUTPUT_DIR]"
    echo ""
    echo "EXAMPLES:"
    echo "  # Scan Ubuntu 20.04"
    echo "  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \\"
    echo "             -v \$(pwd)/results:/results \\"
    echo "             stl-cyber/container-scanner:latest ubuntu:20.04"
    echo ""
    echo "  # Scan custom image with specific output directory"
    echo "  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \\"
    echo "             -v \$(pwd)/results:/results \\"
    echo "             stl-cyber/container-scanner:latest myapp:latest /results/myapp-scan"
    echo ""
    echo "OUTPUT REPORTS:"
    echo "  • Vulnerability Reports (HTML, TBL, JSON)"
    echo "  • License Compliance (OSI validation + DoD approval)"
    echo "  • Foreign Ownership Analysis (CFIUS compliance)"
    echo "  • Threat Intelligence Cross-Reference (NVD, CERT, Exploit-DB, Talos)"
    echo "  • Unified Compliance Report (CSV, TXT, JSON, HTML)"
    echo "  • SBOM (CycloneDX)"
    echo "  • NIST 800-53 Mapping (HDF, XCCDF, CKL)"
    echo ""
    exit 0
fi

IMAGE_NAME="$1"
OUTPUT_DIR="${2:-/results/scan_$(date +%Y%m%d_%H%M%S)}"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

echo "Target Image: $IMAGE_NAME"
echo "Output Directory: $OUTPUT_DIR"
echo ""
echo "Starting scan... (this may take several minutes)"
echo ""

# Run the scanner
cd /app
./improved.sh "$IMAGE_NAME" "$OUTPUT_DIR"

echo ""
echo "================================================================"
echo "                    SCAN COMPLETE"
echo "================================================================"
echo ""
echo "Results saved to: $OUTPUT_DIR"
echo ""
echo "KEY FILES:"
echo "  - Unified Compliance: $OUTPUT_DIR/reports/*_unified_compliance_*.csv"
echo "  - Foreign Ownership: $OUTPUT_DIR/reports/*_foreign_ownership_*.txt"
echo "  - Vulnerabilities: $OUTPUT_DIR/reports/*_vulnerabilities_*.html"
echo "  - Licenses: $OUTPUT_DIR/reports/*_licenses_*.html"
echo "  - Threat Intel: $OUTPUT_DIR/reports/*_threat_intel_*.html"
echo "  - SBOM: $OUTPUT_DIR/MITRE/*_cyclonedx_*.json"
echo "  - NIST 800-53: $OUTPUT_DIR/MITRE/hdf/*_trivy-hdf_*.json"
echo ""
