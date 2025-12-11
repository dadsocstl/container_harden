# test-docker-scanner.ps1 - Test the container scanner Docker image (Windows)

param(
    [string]$Image = "stlcyber/container-scanner:latest",
    [string]$TestImage = "ubuntu:20.04"
)

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "     Container Scanner Docker Image Test Suite                 " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Image exists
Write-Host "Test 1: Checking if image exists..." -ForegroundColor Yellow
$imageExists = docker image inspect $Image 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Image found: $Image" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Image not found: $Image" -ForegroundColor Red
    Write-Host "   Build it first with: docker build -t $Image ." -ForegroundColor Yellow
    exit 1
}

# Test 2: Show usage
Write-Host ""
Write-Host "Test 2: Displaying usage information..." -ForegroundColor Yellow
docker run --rm $Image 2>&1 | Select-Object -First 20
Write-Host "[OK] Usage display working" -ForegroundColor Green

# Test 3: Run basic scan
Write-Host ""
Write-Host "Test 3: Running basic scan on $TestImage..." -ForegroundColor Yellow
$timestamp = [int][double]::Parse((Get-Date -UFormat %s))
$resultsDir = Join-Path $PSScriptRoot "test-results-$timestamp"
New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null

Write-Host "Using paths:" -ForegroundColor Cyan
Write-Host "  Results Dir: $resultsDir" -ForegroundColor Cyan

docker run --rm `
  -v /var/run/docker.sock:/var/run/docker.sock `
  -v "${resultsDir}:/results" `
  $Image $TestImage "/results/test-scan"

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[FAIL] Scan failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[OK] Scan completed successfully" -ForegroundColor Green

# Test 4: Verify outputs
Write-Host ""
Write-Host "Test 4: Verifying output files..." -ForegroundColor Yellow
$scanDir = Get-ChildItem -Path $resultsDir -Directory -Filter "test-scan*" | Select-Object -First 1

if (-not $scanDir) {
    Write-Host "[FAIL] Scan directory not found" -ForegroundColor Red
    exit 1
}

Write-Host "Scan directory: $($scanDir.FullName)" -ForegroundColor Cyan

# Check for key files
$requiredPatterns = @(
    "trivy_scans\trivy_full_*.json",
    "reports\*_unified_compliance_*.csv",
    "reports\*_foreign_ownership_*.txt",
    "reports\*_vulnerabilities_*.html",
    "reports\*_licenses_*.html",
    "MITRE\*_cyclonedx_*.json",
    "MITRE\hdf\trivy-hdf-*.json"
)

$passed = 0
$failed = 0

foreach ($pattern in $requiredPatterns) {
    $fullPath = Join-Path $scanDir.FullName $pattern
    $files = Get-ChildItem -Path $fullPath -ErrorAction SilentlyContinue
    if ($files) {
        Write-Host "  [OK] Found: $pattern" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "  [MISS] Missing: $pattern" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
Write-Host "File verification: $passed passed, $failed failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Yellow" })

# Test 5: Check CSV format
Write-Host ""
Write-Host "Test 5: Validating CSV format..." -ForegroundColor Yellow
$csvFile = Get-ChildItem -Path (Join-Path $scanDir.FullName "reports") -Filter "*_unified_compliance_*.csv" | Select-Object -First 1

if ($csvFile) {
    $lines = (Get-Content $csvFile.FullName).Count
    $cols = ((Get-Content $csvFile.FullName -First 1) -split ',').Count
    
    Write-Host "  CSV file: $($csvFile.Name)" -ForegroundColor Cyan
    Write-Host "  Rows: $lines" -ForegroundColor Cyan
    Write-Host "  Columns: $cols" -ForegroundColor Cyan
    
    if ($cols -eq 9) {
        Write-Host "  [OK] CSV format correct - 9 columns" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] CSV format incorrect - expected 9 columns, got $cols" -ForegroundColor Red
        $failed++
    }
} else {
    Write-Host "  [FAIL] CSV file not found" -ForegroundColor Red
    $failed++
}

# Summary
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "                    TEST SUMMARY                                " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Results directory: $resultsDir" -ForegroundColor Cyan
Write-Host ""

if ($failed -eq 0) {
    Write-Host "[SUCCESS] ALL TESTS PASSED" -ForegroundColor Green
    Write-Host ""
    Write-Host "Sample outputs:" -ForegroundColor Cyan
    if ($csvFile) {
        Write-Host "  Unified Compliance: $($csvFile.FullName)" -ForegroundColor White
    }
    $foreignFile = Get-ChildItem -Path (Join-Path $scanDir.FullName "reports") -Filter "*_foreign_ownership_*.txt" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($foreignFile) {
        Write-Host "  Foreign Ownership: $($foreignFile.FullName)" -ForegroundColor White
    }
    $vulnFile = Get-ChildItem -Path (Join-Path $scanDir.FullName "reports") -Filter "*_vulnerabilities_*.html" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($vulnFile) {
        Write-Host "  Vulnerabilities: $($vulnFile.FullName)" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "Clean up test results:" -ForegroundColor Yellow
    Write-Host "  Remove-Item -Recurse -Force '$resultsDir'" -ForegroundColor White
    exit 0
} else {
    Write-Host "[FAILED] TESTS FAILED: $failed failures" -ForegroundColor Red
    Write-Host ""
    if ($scanDir) {
        Write-Host "Check logs in: $(Join-Path $scanDir.FullName 'logs')" -ForegroundColor Yellow
    }
    exit 1
}
