#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="$SCRIPT_DIR/../.trivy-cache"
mkdir -p "$CACHE_DIR"

# Tool check
for cmd in trivy jq docker python3; do
    command -v $cmd >/dev/null || { echo "ERROR: $cmd not found"; exit 1; }
done

# Load SAF if needed
if [ -f "$SCRIPT_DIR/utils/docker-load-saf.sh" ]; then
    "$SCRIPT_DIR/utils/docker-load-saf.sh"
fi

# Container Hardening Benchmark Check Script using Trivy
# This script checks container images against the DevSecOps Enterprise Container Hardening Guide
# Based on NIST SP 800-190 and DOD DevSecOps guidelines

echo "Container Hardening Benchmark Checker using Trivy"
echo "=================================================="
echo ""

# Prompt for container image name
read -p "Enter the container image name (e.g., guacamole/guacamole:latest): " IMAGE_NAME

if [ -z "$IMAGE_NAME" ]; then
    echo "Error: No image name provided."
    exit 1
fi

# Prompt for directory name
read -p "Enter the directory name for results (e.g., my_scan_results): " DIRECTORY_NAME

if [ -z "$DIRECTORY_NAME" ]; then
    echo "Error: No directory name provided."
    exit 1
fi

# Generate timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Extract container name
container_name=$(echo "$IMAGE_NAME" | sed 's|.*/||' | sed 's|:.*||')

# Create main directory and subfolders
mkdir -p "$DIRECTORY_NAME/trivy_scans" "$DIRECTORY_NAME/MITRE" "$DIRECTORY_NAME/reports"

echo "Results will be saved in directory: $DIRECTORY_NAME"
echo "Subfolders created: trivy_scans, compliance_files, reports"
echo ""

# Temporary file for results
RESULTS_FILE="$DIRECTORY_NAME/reports/check_results_$TIMESTAMP.txt"
HDF_FILE="container_hardening.hdf.json"
UPDATED_HDF_FILE="$DIRECTORY_NAME/MITRE/temp_hdf_results_$TIMESTAMP.json"

# Function to run trivy and save output
run_check() {
    local control_id="$1"
    local description="$2"
    local cmd="$3"
    local output_file="$4"
    local parse_func="$5"
    
    echo "CH-$control_id: $description" >> "$RESULTS_FILE"
    echo "Command: $cmd" >> "$RESULTS_FILE"
    
    local output
    local error_output
    output=$(eval "$cmd" 2>&1)
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo "ERROR: Command failed with exit code $exit_code for CH-$control_id" >&2
        echo "Command: $cmd" >&2
        echo "Error output: $output" >&2
    fi
    echo "$output" >> "$RESULTS_FILE"
    if [ -n "$output_file" ]; then
        echo "$output" > "$DIRECTORY_NAME/reports/$output_file"
    fi
    echo "" >> "$RESULTS_FILE"
    
    # Call parse function if provided
    if [ -n "$parse_func" ] && [ $exit_code -eq 0 ]; then
        $parse_func "$control_id" "$output"
    fi
}

# Parse functions for automated checks
parse_registry() {
    local control_id="$1"
    local output="$2"
    # CH-01: Pass if registry is ironbank or repo1, fail otherwise
    if echo "$output" | grep -q -E "(ironbank|repo1)"; then
        RESULTS["$control_id"]="passed"
        jq --arg id "CH-0$control_id" --arg status "passed" --arg desc "Image sourced from approved registry (ironbank or repo1)." '
            .profiles[0].controls |= map(
                if .id == $id then
                    .results[0].status = $status |
                    .results[0].code_desc = $desc |
                    .descriptions.check = "Verified registry: $output"
                else . end
            )
        ' "$UPDATED_HDF_FILE" > tmp.json && mv tmp.json "$UPDATED_HDF_FILE"
    else
        RESULTS["$control_id"]="failed"
        jq --arg id "CH-0$control_id" --arg status "failed" --arg desc "Image not sourced from approved registry (ironbank or repo1). Found: $output" '
            .profiles[0].controls |= map(
                if .id == $id then
                    .results[0].status = $status |
                    .results[0].code_desc = $desc |
                    .descriptions.check = "Registry check failed. Expected ironbank or repo1, found: $output"
                else . end
            )
        ' "$UPDATED_HDF_FILE" > tmp.json && mv tmp.json "$UPDATED_HDF_FILE"
    fi
}

parse_vulns() {
    local control_id="$1"
    local output="$2"
    # CH-02: Check for HIGH/CRITICAL vulnerabilities
    local trivy_version
    trivy_version=$(trivy --version 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    
    local vuln_count
    vuln_count=$(echo "$output" | grep -c -E "(HIGH|CRITICAL)" || echo "0")
    
    local check_content="Vulnerability scan performed using Trivy $trivy_version. "
    if [ "$vuln_count" -gt 0 ]; then
        RESULTS["$control_id"]="failed"
        check_content+="Found $vuln_count HIGH/CRITICAL vulnerabilities. Details: $(echo "$output" | grep -E "(HIGH|CRITICAL)" | head -5 | tr '\n' '; ')"
    else
        RESULTS["$control_id"]="passed"
        check_content+="No HIGH/CRITICAL vulnerabilities found."
    fi
    
    # Update HDF with results and check content
    jq --arg id "CH-0$control_id" --arg status "${RESULTS[$control_id]}" --arg desc "$check_content" --arg code_desc "Scanned with Trivy $trivy_version" '
        .profiles[0].controls |= map(
            if .id == $id then
                .results[0].status = $status |
                .results[0].code_desc = $code_desc |
                .descriptions.check = $desc
            else . end
        )
    ' "$UPDATED_HDF_FILE" > tmp.json && mv tmp.json "$UPDATED_HDF_FILE"
}

parse_user() {
    local control_id="$1"
    local output="$2"
    # CH-03: Pass if user is not root or empty
    if [ "$output" = "root" ] || [ -z "$output" ]; then
        RESULTS["$control_id"]="failed"
    else
        RESULTS["$control_id"]="passed"
    fi
}

parse_secrets() {
    local control_id="$1"
    local output="$2"
    # CH-05: Fail if secrets found
    if echo "$output" | grep -q -i "secret"; then
        RESULTS["$control_id"]="failed"
    else
        RESULTS["$control_id"]="passed"
    fi
}

parse_hash() {
    local control_id="$1"
    local output="$2"
    # CH-08: Hash validation - check if digest exists and is valid sha256
    if echo "$output" | grep -q "sha256:"; then
        RESULTS["$control_id"]="passed"
        jq --arg id "CH-0$control_id" --arg status "passed" --arg desc "Image hash validated: $output" '
            .profiles[0].controls |= map(
                if .id == $id then
                    .results[0].status = $status |
                    .results[0].code_desc = $desc |
                    .descriptions.check = "Image digest verified: $output"
                else . end
            )
        ' "$UPDATED_HDF_FILE" > tmp.json && mv tmp.json "$UPDATED_HDF_FILE"
    else
        RESULTS["$control_id"]="failed"
        jq --arg id "CH-0$control_id" --arg status "failed" --arg desc "Image hash validation failed. Digest: $output" '
            .profiles[0].controls |= map(
                if .id == $id then
                    .results[0].status = $status |
                    .results[0].code_desc = $desc |
                    .descriptions.check = "No valid sha256 digest found: $output"
                else . end
            )
        ' "$UPDATED_HDF_FILE" > tmp.json && mv tmp.json "$UPDATED_HDF_FILE"
    fi
}

# Initialize results array
declare -A RESULTS
for i in {1..10}; do
    RESULTS["$i"]="not_reviewed"
done

# Check dependencies
# Dependencies checked in header

# Run comprehensive Trivy scans and save outputs
echo "Running comprehensive scans..."
if ! trivy image --scanners vuln,secret --format json --output "$DIRECTORY_NAME/trivy_scans/trivy_full_$TIMESTAMP.json" "$IMAGE_NAME" 2>&1; then
    echo "ERROR: Failed to run full Trivy scan" >&2
fi
if ! trivy image --scanners vuln --format json --output "$DIRECTORY_NAME/trivy_scans/trivy_vulns_$TIMESTAMP.json" "$IMAGE_NAME" 2>&1; then
    echo "ERROR: Failed to run vulnerability scan" >&2
fi
if ! trivy image --scanners secret --format json --output "$DIRECTORY_NAME/trivy_scans/trivy_secrets_$TIMESTAMP.json" "$IMAGE_NAME" 2>&1; then
    echo "ERROR: Failed to run secret scan" >&2
fi
if ! trivy image --scanners misconfig --format json --output "$DIRECTORY_NAME/trivy_scans/trivy_config_$TIMESTAMP.json" "$IMAGE_NAME" 2>&1; then
    echo "ERROR: Failed to run config scan" >&2
fi

## License check
if ! trivy image \
  --scanners vuln,license \
  --format cyclonedx \
  --output "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_cyclonedx_$TIMESTAMP.json" \
  --quiet \
  "$IMAGE_NAME"; then
    echo "ERROR: Failed to generate CycloneDX SBOM with licenses" >&2
    exit 1
fi

# Also export human-readable license table (for auditors)
trivy image \
  --scanners license \
  --format template \
  --template "@contrib/license-table.tpl" \
  --output "$DIRECTORY_NAME/reports/${DIRECTORY_NAME}_licenses_$TIMESTAMP.html" \
  "$IMAGE_NAME" > /dev/null 2>&1

# FINAL LICENSE COMPLIANCE GATE — FAIL BUILD ON BAD LICENSES
if trivy image --scanners license --format json --quiet "$IMAGE_NAME" 2>/dev/null | \
   jq -e '
     .Results[].Licenses // [] 
     | any(
         test("AGPL|SSPL|Proprietary|Commercial|Elastic License|Server Side Public"; "i")
       )' > /dev/null; then
    echo ""
    echo "FATAL: FORBIDDEN LICENSE DETECTED — BUILD REJECTED" >&2
    echo "       AGPL, SSPL, Proprietary, or other non-approved licenses found" >&2
    echo "       See: $DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_cyclonedx_$TIMESTAMP.json" >&2
    echo "       and $DIRECTORY_NAME/reports/${DIRECTORY_NAME}_licenses_$TIMESTAMP.html" >&2
    echo ""
    exit 1
else
    echo "License compliance passed — only approved licenses (GPL, MIT, Apache, BSD, etc.)"
fi

# Generate HTML report
if ! trivy image --format template --template "@contrib/html.tpl" --output "$DIRECTORY_NAME/reports/trivy_report_$TIMESTAMP.html" "$IMAGE_NAME" 2>&1; then
    echo "ERROR: Failed to generate HTML report" >&2
fi

# Generate CycloneDX SBOM
if ! trivy image --format cyclonedx --output "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_cyclonedx_$TIMESTAMP.json" "$IMAGE_NAME" 2>&1; then
    echo "ERROR: Failed to generate CycloneDX SBOM" >&2
fi

# Run checks
run_check "01" "Ensure container images are sourced from trusted registries" "jq -r '.Metadata.RepoDigests[0] // \"No digest found\"' \"$DIRECTORY_NAME/trivy_scans/trivy_full_$TIMESTAMP.json\"" "registry_check_$TIMESTAMP.txt" "parse_registry"

run_check "02" "Ensure container images are scanned for vulnerabilities" "jq '.Results[0].Vulnerabilities | length' \"$DIRECTORY_NAME/trivy_scans/trivy_full_$TIMESTAMP.json\"" "vulns_check_$TIMESTAMP.txt" "parse_vulns"

run_check "03" "Ensure containers run with non-root user privileges" "jq -r '.Config.User // \"root\"' \"$DIRECTORY_NAME/trivy_scans/trivy_full_$TIMESTAMP.json\"" "user_check_$TIMESTAMP.txt" "parse_user"

run_check "04" "Ensure minimal attack surface by removing unnecessary packages" "jq '.Packages | length' \"$DIRECTORY_NAME/trivy_scans/trivy_full_$TIMESTAMP.json\"" "packages_check_$TIMESTAMP.txt"

run_check "05" "Ensure secrets are managed securely" "jq '.Results[0].Secrets | length' \"$DIRECTORY_NAME/trivy_scans/trivy_full_$TIMESTAMP.json\"" "secrets_check_$TIMESTAMP.txt" "parse_secrets"

run_check "06" "Ensure resource limits are set" "echo 'Manual: Check deployment configs for --cpus, --memory limits'" "limits_check_$TIMESTAMP.txt"

run_check "07" "Ensure logging is enabled and configured" "echo 'Manual: Check runtime logging configuration'" "logging_check_$TIMESTAMP.txt"

run_check "08" "Ensure container images have valid hash digests" "jq -r '.Metadata.RepoDigests[0] // \"No digest found\"' \"$DIRECTORY_NAME/trivy_scans/trivy_full_$TIMESTAMP.json\"" "signature_check_$TIMESTAMP.txt" "parse_hash"

run_check "09" "Ensure network policies are implemented" "echo 'Manual: Check network policies at runtime/orchestration level'" "network_check_$TIMESTAMP.txt"

run_check "10" "Ensure regular updates and patch management" "jq '.Packages[]? | select(.Name? | test(\"(openssl|curl|wget|bash|coreutils)\"; \"i\")) | \"\(.Name): \(.Version)\"' \"$DIRECTORY_NAME/trivy_scans/trivy_full_$TIMESTAMP.json\" | head -5" "updates_check_$TIMESTAMP.txt"

# Display results
echo "Check Results Summary:"
echo "======================"
cat "$RESULTS_FILE"

# Update HDF with results
cp "$HDF_FILE" "$UPDATED_HDF_FILE"
for i in {1..10}; do
    status="${RESULTS[$i]}"
    if [ "$status" != "not_reviewed" ]; then
        # Update the HDF file
        jq --arg id "CH-0$i" --arg status "$status" '
            .profiles[0].controls |= map(
                if .id == $id then
                    .results[0].status = $status
                else . end
            )
        ' "$UPDATED_HDF_FILE" > tmp.json && mv tmp.json "$UPDATED_HDF_FILE"
    fi
done

# Generate compliance files automatically
echo "Generating compliance files..."

# Initialize success flags
CKL_SUCCESS=false
XCCDF_SUCCESS=false
OSCAP_SUCCESS=false

# Initialize fatal errors
FATAL_ERRORS=""

# CKL
echo "Generating CKL file..."
# Create metadata for CKL
cat > "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_metadata_$TIMESTAMP.json" << EOF
{
  "profiles": [
    {
      "name": "DevSecOps Internal Containers",
      "title": "DevSecOps Enterprise Container Hardening Guide",
      "version": "1.2",
      "release": "1.0",
      "asset": {
        "name": "$container_name",
        "type": "container",
        "classification": "Unclass"
      }
    }
  ]
}
EOF

CKL_OUTPUT=$(saf convert hdf2ckl -i "$UPDATED_HDF_FILE" -m "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_metadata_$TIMESTAMP.json" -o "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_$TIMESTAMP.ckl" 2>&1)
CKL_EXIT_CODE=$?
if [ $CKL_EXIT_CODE -eq 0 ]; then
    CKL_SUCCESS=true
    echo "CKL file generated successfully"
    # Update the STATUS in CKL with actual results
    for i in {1..10}; do
        status="${RESULTS[$i]}"
        if [ "$status" = "passed" ]; then
            ckl_status="NotAFinding"
        elif [ "$status" = "failed" ]; then
            ckl_status="Open"
        else
            ckl_status="Not_Reviewed"
        fi
        # Find the VULN block for CH-0$i and update STATUS
        sed -i "/<ATTRIBUTE_DATA>CH-0${i}<\/ATTRIBUTE_DATA>/,/<\/VULN>/ s|<STATUS>[^<]*</STATUS>|<STATUS>$ckl_status</STATUS>|" "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_$TIMESTAMP.ckl"
    done
else
    CKL_SUCCESS=false
    FATAL_ERRORS="$FATAL_ERRORS\nERROR: Failed to generate CKL file (exit code: $CKL_EXIT_CODE)\nSAF output: $CKL_OUTPUT"
fi

# XCCDF
echo "Generating XCCDF file..."
XCCDF_OUTPUT=$(saf convert hdf2xccdf -i "$UPDATED_HDF_FILE" -o "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_$TIMESTAMP.xccdf.xml" 2>&1)
XCCDF_EXIT_CODE=$?
if [ $XCCDF_EXIT_CODE -eq 0 ]; then
    XCCDF_SUCCESS=true
    echo "XCCDF file generated successfully"
    # Update the TestResult with actual results
    for i in {1..10}; do
        status="${RESULTS[$i]}"
        if [ "$status" = "passed" ]; then
            result="pass"
        elif [ "$status" = "failed" ]; then
            result="fail"
        else
            result="unknown"
        fi
        sed -i "/<rule-result idref=\"xccdf_hdf_rule_CH-0${i}_rule\">/,/<\/rule-result>/ s|<result>unknown</result>|<result>$result</result>|" "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_$TIMESTAMP.xccdf.xml"
    done
else
    XCCDF_SUCCESS=false
    FATAL_ERRORS="$FATAL_ERRORS\nERROR: Failed to generate XCCDF file (exit code: $XCCDF_EXIT_CODE)\nSAF output: $XCCDF_OUTPUT"
fi

# Try OSCAP evaluation if oscap is available
if command -v oscap &> /dev/null; then
    echo "Running OSCAP evaluation..."
    if oscap xccdf eval --results "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_oscap_results_$TIMESTAMP.xml" "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_$TIMESTAMP.xccdf.xml" 2>&1 && \
       oscap xccdf generate report "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_oscap_results_$TIMESTAMP.xml" > "$DIRECTORY_NAME/reports/${DIRECTORY_NAME}_oscap_report_$TIMESTAMP.html" 2>&1; then
        OSCAP_SUCCESS=true
    else
        OSCAP_SUCCESS=false
        echo "ERROR: Failed to run OSCAP evaluation" >&2
    fi
else
    OSCAP_SUCCESS=false
    echo "OSCAP not found. Install OpenSCAP for additional OSCAP results."
fi

echo ""
echo "All results saved in directory: $DIRECTORY_NAME"
echo "Files generated:"
if [ -f "$DIRECTORY_NAME/trivy_scans/trivy_full_$TIMESTAMP.json" ]; then
    echo -e "\033[32m  - trivy_scans/trivy_full_$TIMESTAMP.json: Complete Trivy scan results\033[0m"
else
    echo -e "\033[31m  - trivy_scans/trivy_full_$TIMESTAMP.json: Complete Trivy scan results - FAILED\033[0m"
fi
if [ -f "$DIRECTORY_NAME/trivy_scans/trivy_vulns_$TIMESTAMP.json" ]; then
    echo -e "\033[32m  - trivy_scans/trivy_vulns_$TIMESTAMP.json: Vulnerability scan\033[0m"
else
    echo -e "\033[31m  - trivy_scans/trivy_vulns_$TIMESTAMP.json: Vulnerability scan - FAILED\033[0m"
fi
if [ -f "$DIRECTORY_NAME/trivy_scans/trivy_secrets_$TIMESTAMP.json" ]; then
    echo -e "\033[32m  - trivy_scans/trivy_secrets_$TIMESTAMP.json: Secret scan\033[0m"
else
    echo -e "\033[31m  - trivy_scans/trivy_secrets_$TIMESTAMP.json: Secret scan - FAILED\033[0m"
fi
if [ -f "$DIRECTORY_NAME/trivy_scans/trivy_config_$TIMESTAMP.json" ]; then
    echo -e "\033[32m  - trivy_scans/trivy_config_$TIMESTAMP.json: Configuration scan\033[0m"
else
    echo -e "\033[31m  - trivy_scans/trivy_config_$TIMESTAMP.json: Configuration scan - FAILED\033[0m"
fi
if [ -f "$DIRECTORY_NAME/reports/trivy_report_$TIMESTAMP.html" ]; then
    echo -e "\033[32m  - reports/trivy_report_$TIMESTAMP.html: HTML vulnerability report\033[0m"
else
    echo -e "\033[31m  - reports/trivy_report_$TIMESTAMP.html: HTML vulnerability report - FAILED\033[0m"
fi
if [ "$CKL_SUCCESS" = true ] && [ -f "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_$TIMESTAMP.ckl" ]; then
    echo -e "\033[32m  - MITRE/${DIRECTORY_NAME}_$TIMESTAMP.ckl: STIG Checklist (CKL)\033[0m"
else
    echo -e "\033[31m  - MITRE/${DIRECTORY_NAME}_$TIMESTAMP.ckl: STIG Checklist (CKL) - FAILED\033[0m"
fi
if [ "$XCCDF_SUCCESS" = true ] && [ -f "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_$TIMESTAMP.xccdf.xml" ]; then
    echo -e "\033[32m  - MITRE/${DIRECTORY_NAME}_$TIMESTAMP.xccdf.xml: XCCDF benchmark\033[0m"
else
    echo -e "\033[31m  - MITRE/${DIRECTORY_NAME}_$TIMESTAMP.xccdf.xml: XCCDF benchmark - FAILED\033[0m"
fi
if [ -f "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_cyclonedx_$TIMESTAMP.json" ]; then
    echo -e "\033[32m  - MITRE/${DIRECTORY_NAME}_cyclonedx_$TIMESTAMP.json: CycloneDX SBOM\033[0m"
else
    echo -e "\033[31m  - MITRE/${DIRECTORY_NAME}_cyclonedx_$TIMESTAMP.json: CycloneDX SBOM - FAILED\033[0m"
fi
if [ "$OSCAP_SUCCESS" = true ] && [ -f "$DIRECTORY_NAME/MITRE/${DIRECTORY_NAME}_oscap_results_$TIMESTAMP.xml" ] && [ -f "$DIRECTORY_NAME/reports/${DIRECTORY_NAME}_oscap_report_$TIMESTAMP.html" ]; then
    echo -e "\033[32m  - MITRE/${DIRECTORY_NAME}_oscap_results_$TIMESTAMP.xml: OSCAP evaluation results\033[0m"
    echo -e "\033[32m  - reports/${DIRECTORY_NAME}_oscap_report_$TIMESTAMP.html: OSCAP HTML report\033[0m"
elif command -v oscap &> /dev/null; then
    echo -e "\033[31m  - OSCAP results: FAILED\033[0m"
fi
if [ -f "$DIRECTORY_NAME/reports/check_results_$TIMESTAMP.txt" ]; then
    echo -e "\033[32m  - reports/check_results_$TIMESTAMP.txt: Summary of all checks\033[0m"
else
    echo -e "\033[31m  - reports/check_results_$TIMESTAMP.txt: Summary of all checks - FAILED\033[0m"
fi
echo -e "\033[32m  - reports/Individual check files (*.txt)\033[0m"

# Echo fatal errors at the end
if [ -n "$FATAL_ERRORS" ]; then
    echo ""
    echo "Fatal Errors:"
    echo -e "$FATAL_ERRORS"
fi

# Cleanup temp file
rm -f "$UPDATED_HDF_FILE"

echo "Script completed."

# Optional: Run NIST compliance report
echo ""
echo "Optional: Generate NIST 800-53 compliance report from the Trivy scan?"
read -p "Run trivy_to_nist.py on the scan results? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -f "$DIRECTORY_NAME/trivy_scans/trivy_full_$TIMESTAMP.json" ]; then
        if command -v python3 &> /dev/null; then
            python3 trivy_to_nist.py "$DIRECTORY_NAME/trivy_scans/trivy_full_$TIMESTAMP.json" "$DIRECTORY_NAME"
        else
            echo "Python3 not found. Please install Python3 to run the NIST report."
        fi
    else
        echo "Trivy scan results not found. Cannot generate NIST report."
    fi
fi