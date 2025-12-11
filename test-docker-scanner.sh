#!/bin/bash
# test-docker-scanner.sh - Test the container scanner Docker image

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         Container Scanner Docker Image Test Suite           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

IMAGE="${1:-stlcyber/container-scanner:latest}"
TEST_IMAGE="ubuntu:20.04"

# Detect OS and set Docker socket path
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    # Windows (Git Bash/MINGW)
    DOCKER_SOCKET="//var/run/docker.sock"
    RESULTS_DIR="$(pwd -W 2>/dev/null || pwd)/test-results-$(date +%s)"
    RESULTS_DIR="${RESULTS_DIR//\\/\/}"  # Convert backslashes to forward slashes
else
    # Linux/Mac
    DOCKER_SOCKET="/var/run/docker.sock"
    RESULTS_DIR="$(pwd)/test-results-$(date +%s)"
fi

# Test 1: Image exists
echo "Test 1: Checking if image exists..."
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "✅ Image found: $IMAGE"
else
    echo "❌ Image not found: $IMAGE"
    echo "   Build it first with: docker build -t $IMAGE ."
    exit 1
fi

# Test 2: Show usage
echo ""
echo "Test 2: Displaying usage information..."
docker run --rm "$IMAGE" 2>&1 | head -20
echo "✅ Usage display working"

# Test 3: Run basic scan
echo ""
echo "Test 3: Running basic scan on $TEST_IMAGE..."
mkdir -p "$RESULTS_DIR"

echo "Using paths:"
echo "  Docker Socket: $DOCKER_SOCKET"
echo "  Results Dir: $RESULTS_DIR"

docker run --rm \
  -v "$DOCKER_SOCKET:/var/run/docker.sock" \
  -v "$RESULTS_DIR:/results" \
  "$IMAGE" "$TEST_IMAGE" "/results/test-scan"

echo ""
echo "✅ Scan completed successfully"

# Test 4: Verify outputs
echo ""
echo "Test 4: Verifying output files..."
SCAN_DIR=$(find "$RESULTS_DIR" -type d -name "test-scan*" | head -1)

if [ -z "$SCAN_DIR" ]; then
    echo "❌ Scan directory not found"
    exit 1
fi

echo "Scan directory: $SCAN_DIR"

# Check for key files
REQUIRED_FILES=(
    "trivy_scans/trivy_full_*.json"
    "reports/*_unified_compliance_*.csv"
    "reports/*_foreign_ownership_*.txt"
    "reports/*_vulnerabilities_*.html"
    "reports/*_licenses_*.html"
    "MITRE/*_cyclonedx_*.json"
    "MITRE/hdf/trivy-hdf-*.json"
)

PASSED=0
FAILED=0

for pattern in "${REQUIRED_FILES[@]}"; do
    if compgen -G "$SCAN_DIR/$pattern" >/dev/null; then
        echo "  ✅ Found: $pattern"
        ((PASSED++))
    else
        echo "  ❌ Missing: $pattern"
        ((FAILED++))
    fi
done

echo ""
echo "File verification: $PASSED passed, $FAILED failed"

# Test 5: Check CSV format
echo ""
echo "Test 5: Validating CSV format..."
CSV_FILE=$(find "$SCAN_DIR/reports" -name "*_unified_compliance_*.csv" | head -1)
if [ -f "$CSV_FILE" ]; then
    LINES=$(wc -l < "$CSV_FILE")
    COLS=$(head -1 "$CSV_FILE" | awk -F',' '{print NF}')
    echo "  CSV file: $(basename $CSV_FILE)"
    echo "  Rows: $LINES"
    echo "  Columns: $COLS"
    
    if [ "$COLS" -eq 9 ]; then
        echo "  ✅ CSV format correct (9 columns)"
    else
        echo "  ❌ CSV format incorrect (expected 9 columns, got $COLS)"
        ((FAILED++))
    fi
else
    echo "  ❌ CSV file not found"
    ((FAILED++))
fi

# Test 6: Check JSON validity
echo ""
echo "Test 6: Validating JSON files..."
for json in "$SCAN_DIR"/trivy_scans/*.json "$SCAN_DIR"/reports/*.json "$SCAN_DIR"/MITRE/*.json; do
    if [ -f "$json" ]; then
        if jq empty "$json" 2>/dev/null; then
            echo "  ✅ Valid: $(basename $json)"
        else
            echo "  ❌ Invalid: $(basename $json)"
            ((FAILED++))
        fi
    fi
done

# Summary
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                      TEST SUMMARY                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Results directory: $RESULTS_DIR"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "✅ ALL TESTS PASSED"
    echo ""
    echo "Sample outputs:"
    echo "  Unified Compliance: $CSV_FILE"
    echo "  Foreign Ownership: $(find "$SCAN_DIR/reports" -name "*_foreign_ownership_*.txt" | head -1)"
    echo "  Vulnerabilities: $(find "$SCAN_DIR/reports" -name "*_vulnerabilities_*.html" | head -1)"
    echo ""
    echo "Clean up test results:"
    echo "  rm -rf $RESULTS_DIR"
    exit 0
else
    echo "❌ TESTS FAILED: $FAILED failures"
    echo ""
    echo "Check logs in: $SCAN_DIR/logs/"
    exit 1
fi
