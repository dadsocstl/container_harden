# Unified Compliance Report - CSV Format Reference

## File Location
`reports/{container_name}_unified_compliance_{timestamp}.csv`

## CSV Column Structure

| Column | Description | Example Values |
|--------|-------------|----------------|
| Package Name | Software package identifier | `libc6`, `bash`, `nginx` |
| Version | Package version number | `2.31-0ubuntu9.17`, `5.0` |
| Licenses | Comma-separated license list | `GPL-2.0-only, MIT` |
| Country of Origin | ISO 2-letter country code | `US`, `GB`, `RU`, `CN`, `UNKNOWN` |
| Organization | Developer/maintainer organization | `GNU Project`, `Apache Foundation` |
| License Status | OSI approval status | `OSI-APPROVED`, `NON-OSI` |
| Risk Classification | Combined risk level | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| Application | Container image name | `ubuntu:20.04`, `nginx:latest` |
| Summary | Risk description | `Adversary nation software requiring immediate review` |

## Risk Classification Criteria

### CRITICAL
- **Criteria**: Software from adversary nations (Russia, China, Iran, North Korea)
- **Action**: IMMEDIATE REVIEW REQUIRED - CFIUS approval mandatory
- **Examples**: RU-origin packages, CN-origin packages
- **Priority**: P0 - Block deployment until approved

### HIGH
- **Criteria**: Foreign-origin software (non-US, non-adversary)
- **Action**: CFIUS assessment and supply chain review required
- **Examples**: European, Australian, Japanese software
- **Priority**: P1 - Approval before production deployment

### MEDIUM
- **Criteria**: Non-OSI-approved licenses (US or unknown origin)
- **Action**: Legal counsel review required
- **Examples**: Proprietary licenses, custom licenses
- **Priority**: P2 - Legal approval before deployment

### LOW
- **Criteria**: US-origin with OSI-approved licenses
- **Action**: No additional approval required
- **Examples**: GNU Project, Apache Foundation
- **Priority**: P3 - Standard deployment process

## CSV Import Examples

### Excel / Google Sheets
1. Open application
2. File → Import → CSV
3. Select delimiter: Comma
4. Enable "Text qualifier": Double quote
5. Import all columns as text

### Python pandas
```python
import pandas as pd

df = pd.read_csv('ubuntu2004_unified_compliance_20251211_051339.csv')

# Filter high-risk packages
critical = df[df['Risk Classification'] == 'CRITICAL']
high = df[df['Risk Classification'] == 'HIGH']

# Group by country
by_country = df.groupby('Country of Origin').size()

# Non-OSI licenses
non_osi = df[df['License Status'] == 'NON-OSI']
```

### PowerShell
```powershell
$data = Import-Csv "ubuntu2004_unified_compliance_20251211_051339.csv"

# Filter critical risks
$critical = $data | Where-Object { $_.'Risk Classification' -eq 'CRITICAL' }

# Group by country
$byCountry = $data | Group-Object 'Country of Origin'

# Export filtered data
$critical | Export-Csv "critical_packages.csv" -NoTypeInformation
```

### Database Import (PostgreSQL)
```sql
CREATE TABLE compliance_packages (
    package_name TEXT,
    version TEXT,
    licenses TEXT,
    country_of_origin TEXT,
    organization TEXT,
    license_status TEXT,
    risk_classification TEXT,
    application TEXT,
    summary TEXT
);

\COPY compliance_packages FROM 'ubuntu2004_unified_compliance_20251211_051339.csv' CSV HEADER;

-- Query high-risk packages
SELECT * FROM compliance_packages 
WHERE risk_classification IN ('CRITICAL', 'HIGH')
ORDER BY risk_classification, package_name;
```

## Compliance Workflow

### 1. Export and Review
```bash
# Generate report
./improved.sh ubuntu:20.04 ubuntu/20.04/scan_$(date +%Y%m%d_%H%M%S)

# Open CSV in Excel
xdg-open reports/*_unified_compliance_*.csv
```

### 2. Filter and Categorize
- Sort by Risk Classification (CRITICAL → LOW)
- Filter by Country of Origin
- Filter by License Status

### 3. Track Approvals
Add columns to CSV:
- Approval Status: `PENDING`, `APPROVED`, `REJECTED`
- Approver: Name/email
- Approval Date: YYYY-MM-DD
- Approval Document: Link/reference number
- Notes: Additional context

### 4. Maintain Historical Records
```bash
# Merge multiple scans into master CSV
cat reports/*_unified_compliance_*.csv | \
  sort -u > master_compliance_tracking.csv
```

## Integration with Compliance Systems

### JIRA/ServiceNow Tickets
- Import CSV to create tickets for each high-risk package
- Track approval workflow in ticket system
- Link to authorization documents

### Continuous Monitoring
- Re-scan containers on schedule
- Compare CSV files to detect new risks
- Alert on risk classification changes

### Authorization Package
- Include CSV in System Security Plan (SSP)
- Attach to Security Authorization Package
- Reference in POAM for outstanding approvals

## Report Retention

### DoD/Federal Requirements
- Maintain compliance reports for system lifecycle
- Store in authorization package repository
- Update annually or upon significant changes
- Archive for audit trails (typically 3-7 years)

### Version Control
```bash
# Add to git repository
git add reports/*_unified_compliance_*.csv
git commit -m "Compliance scan: ubuntu:20.04 - $(date +%Y%m%d)"
git tag "scan-$(date +%Y%m%d)"
```

## Additional Resources

- CFIUS: https://home.treasury.gov/policy-issues/international/cfius
- DoD CIO OSS Policy: Search "DoD CIO Open Source Software Memo 2009"
- NIST SP 800-161: https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final
- OSI Licenses: https://opensource.org/licenses/
- Executive Order 13873: Federal Register 2019-10538
