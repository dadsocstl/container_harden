#!/bin/bash
# generate_html_reports.sh
# Generate HTML reports from Trivy JSON files with CSS styling

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <scan_directory>"
    exit 1
fi

SCAN_DIR="$1"
REPORTS_DIR="$SCAN_DIR/reports"

mkdir -p "$REPORTS_DIR"

# CSS for styling
CSS='<style>
table { border-collapse: collapse; width: 100%; font-family: Arial, sans-serif; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
tr:nth-child(even) { background-color: #f9f9f9; }
tr:hover { background-color: #f5f5f5; }
.severity-LOW { background-color: #e9c60060; }
.severity-MEDIUM { background-color: #ff880060; }
.severity-HIGH { background-color: #e4000060; }
.severity-CRITICAL { background-color: #74747460; }
</style>'

# Function to generate HTML for vulnerabilities
generate_vuln_html() {
    local json_file="$1"
    local html_file="$2"
    jq -r --arg css "$CSS" '
    "<html><head><title>Vulnerabilities Report</title>" + $css + "</head><body><h1>Vulnerabilities</h1><table><tr><th>Package</th><th>Vulnerability ID</th><th>Severity</th><th>Installed Version</th></tr>" +
    ([.Results[] | .Vulnerabilities[]? // [] | "<tr class=\"severity-" + .Severity + "\"><td>" + .PkgName + "</td><td>" + .VulnerabilityID + "</td><td>" + .Severity + "</td><td>" + .InstalledVersion + "</td></tr>"] | join("")) +
    "</table></body></html>"
    ' "$json_file" > "$html_file"
}

# Function for secrets
generate_secret_html() {
    local json_file="$1"
    local html_file="$2"
    jq -r --arg css "$CSS" '
    "<html><head><title>Secrets Report</title>" + $css + "</head><body><h1>Secrets</h1><table><tr><th>Rule ID</th><th>Severity</th><th>Match</th><th>Start Line</th></tr>" +
    ([.Results[] | .Secrets | arrays | .[] | "<tr class=\"severity-" + .Severity + "\"><td>" + .RuleID + "</td><td>" + .Severity + "</td><td>" + .Match + "</td><td>" + (.StartLine | tostring) + "</td></tr>"] | join("")) +
    "</table></body></html>"
    ' "$json_file" > "$html_file"
}

# Function for misconfigurations
generate_misconfig_html() {
    local json_file="$1"
    local html_file="$2"
    jq -r --arg css "$CSS" '
    "<html><head><title>Misconfigurations Report</title>" + $css + "</head><body><h1>Misconfigurations</h1><table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Message</th></tr>" +
    ([.Results[] | .Misconfigurations | arrays | .[] | "<tr class=\"severity-" + .Severity + "\"><td>" + .ID + "</td><td>" + .Title + "</td><td>" + .Severity + "</td><td>" + .Message + "</td></tr>"] | join("")) +
    "</table></body></html>"
    ' "$json_file" > "$html_file"
}

# Function for compliance
generate_compliance_html() {
    local json_file="$1"
    local html_file="$2"
    jq -r --arg css "$CSS" '
    "<html><head><title>NIST Compliance Report</title>" + $css + "</head><body><h1>NIST Compliance Report</h1><table><tr><th>ID</th><th>Title</th><th>Results</th></tr>" +
    ([.[] | "<tr><td>" + .ID + "</td><td>" + .Title + "</td><td>" + (.Results | tostring) + "</td></tr>"] | join("")) +
    "</table></body></html>"
    ' "$json_file" > "$html_file"
}

# Function for full report
generate_full_html() {
    local json_file="$1"
    local html_file="$2"
    jq -r --arg css "$CSS" '
    "<html><head><title>Full Trivy Report</title>" + $css + "</head><body><h1>Full Trivy Report</h1>" +
    (if .Results and (.Results | length > 0) then
        "<h2>Vulnerabilities</h2><table><tr><th>Package</th><th>Vulnerability ID</th><th>Severity</th><th>Installed Version</th></tr>" +
        ([.Results[] | .Vulnerabilities[]? // [] | "<tr class=\"severity-" + .Severity + "\"><td>" + .PkgName + "</td><td>" + .VulnerabilityID + "</td><td>" + .Severity + "</td><td>" + .InstalledVersion + "</td></tr>"] | join("")) +
        "</table>"
    else "" end) +
    (if .Results and (.Results | length > 0) then
        "<h2>Secrets</h2><table><tr><th>Rule ID</th><th>Severity</th><th>Match</th><th>Start Line</th></tr>" +
        ([.Results[] | .Secrets | arrays | .[] | "<tr class=\"severity-" + .Severity + "\"><td>" + .RuleID + "</td><td>" + .Severity + "</td><td>" + .Match + "</td><td>" + (.StartLine | tostring) + "</td></tr>"] | join("")) +
        "</table>"
    else "" end) +
    (if .Results and (.Results | length > 0) then
        "<h2>Misconfigurations</h2><table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Message</th></tr>" +
        ([.Results[] | .Misconfigurations | arrays | .[] | "<tr class=\"severity-" + .Severity + "\"><td>" + .ID + "</td><td>" + .Title + "</td><td>" + .Severity + "</td><td>" + .Message + "</td></tr>"] | join("")) +
        "</table>"
    else "" end) +
    "</body></html>"
    ' "$json_file" > "$html_file"
}

# Find and generate
VULN_JSON=$(find "$SCAN_DIR/trivy_scans" -name "vuln_*.json" | head -1)
SECRET_JSON=$(find "$SCAN_DIR/trivy_scans" -name "secret_*.json" | head -1)
MISCONFIG_JSON=$(find "$SCAN_DIR/trivy_scans" -name "misconfig_*.json" | head -1)
COMPLIANCE_JSON=$(find "$SCAN_DIR/trivy_scans" -name "compliance_nist_*.json" | head -1)
FULL_JSON=$(find "$SCAN_DIR/trivy_scans" -name "trivy_full_*.json" | head -1)

if [ -f "$VULN_JSON" ]; then
    generate_vuln_html "$VULN_JSON" "$REPORTS_DIR/vulnerabilities.html"
    echo "Generated vulnerabilities.html"
fi

if [ -f "$SECRET_JSON" ]; then
    generate_secret_html "$SECRET_JSON" "$REPORTS_DIR/secrets.html"
    echo "Generated secrets.html"
fi

if [ -f "$MISCONFIG_JSON" ]; then
    generate_misconfig_html "$MISCONFIG_JSON" "$REPORTS_DIR/misconfigurations.html"
    echo "Generated misconfigurations.html"
fi

if [ -f "$COMPLIANCE_JSON" ]; then
    generate_compliance_html "$COMPLIANCE_JSON" "$REPORTS_DIR/compliance.html"
    echo "Generated compliance.html"
fi

if [ -f "$FULL_JSON" ]; then
    generate_full_html "$FULL_JSON" "$REPORTS_DIR/full_report.html"
    echo "Generated full_report.html"
fi

echo "HTML reports generated in $REPORTS_DIR"