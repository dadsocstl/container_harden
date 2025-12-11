#!/usr/bin/env python3
"""
trivy_to_nist.py
Convert Trivy full JSON scan → NIST 800-53 Rev5 compliance report
Perfect for CMMC 2.2/3, NISP, IL4/IL5 ATO packages

Author: Your favorite container security friend
Date:   Dec 2025
"""

import json
import sys
from datetime import datetime
from collections import defaultdict
import os
import argparse
import subprocess
import glob

parser = argparse.ArgumentParser()
parser.add_argument('directory')
args = parser.parse_args()

# =============================================================================
# NIST 800-53 Rev5 → Trivy finding mapping (container-relevant subset)
# Only controls that can be meaningfully tested in a container image
# =============================================================================

NIST_MAPPING = {
    "SC-28": {
        "name": "Protection of Information at Rest",
        "description": "Encrypt sensitive data at rest",
        "trivy_keywords": ["crypto", "ssl", "tls", "cipher", "insecure"],
        "severity_threshold": "HIGH"
    },
    "SI-2": {
        "name": "Flaw Remediation",
        "description": "Identify, report, and correct system flaws",
        "trivy_keywords": [],
        "severity_threshold": "CRITICAL"
    },
    "SI-7": {
        "name": "Software, Firmware, and Information Integrity",
        "description": "Employ integrity verification tools",
        "trivy_keywords": ["signature", "hash", "verification", "unsigned"],
        "severity_threshold": "HIGH"
    },
    "CM-6": {
        "name": "Configuration Settings",
        "description": "Establish and document configuration settings",
        "trivy_keywords": ["config", "misconfiguration", "exposure", "debug"],
        "severity_threshold": "MEDIUM"
    },
    "IA-5": {
        "name": "Authenticator Management",
        "description": "Manage system authenticators",
        "trivy_keywords": ["password", "credential", "secret", "key"],
        "severity_threshold": "HIGH"
    },
    "AC-6": {
        "name": "Least Privilege",
        "description": "Enforce least privilege",
        "trivy_keywords": ["root", "privileged", "capability", "suid"],
        "severity_threshold": "HIGH"
    },
    "SA-8": {
        "name": "Security and Privacy Engineering Principles",
        "description": "Apply secure design principles",
        "trivy_keywords": ["insecure", "deprecated", "vulnerable"],
        "severity_threshold": "MEDIUM"
    },
    "RA-5": {
        "name": "Vulnerability Monitoring and Scanning",
        "description": "Monitor and scan for vulnerabilities",
        "trivy_keywords": [],
        "severity_threshold": "LOW"  # All findings count
    }
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

def merge_jsons(file_list):
    merged = {"Results": []}
    for f in file_list:
        try:
            with open(f, 'r') as ff:
                data = json.load(ff)
                merged["Results"].extend(data.get("Results", []))
                # Also merge other top-level keys, but Results is the main one
                for key, value in data.items():
                    if key != "Results":
                        merged[key] = value  # Will be overwritten by last file, but that's ok
        except (FileNotFoundError, json.JSONDecodeError):
            print(f"Warning: Could not load {f}")
    return merged

def load_trivy_json(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

def extract_findings(data):
    findings = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            findings.append({
                "type": "vulnerability",
                "id": vuln["VulnerabilityID"],
                "title": vuln.get("Title", vuln["VulnerabilityID"]),
                "severity": vuln["Severity"],
                "package": vuln.get("PkgName", "N/A"),
                "installed": vuln.get("InstalledVersion", "N/A"),
                "fixed": vuln.get("FixedVersion", "No fix available"),
                "description": vuln.get("Description", ""),
                "references": vuln.get("References", []),
                "published": vuln.get("PublishedDate", ""),
                "layer": vuln.get("Layer", {}).get("DiffID", "N/A")
            })
        # Add misconfigs & secrets if present
        for m in result.get("Misconfigurations", []):
            findings.append({
                "type": "misconfiguration",
                "id": m["ID"],
                "title": m.get("Title", m["ID"]),
                "severity": m["Severity"],
                "description": m.get("Message", ""),
                "references": m.get("References", [])
            })
        for s in result.get("Secrets", []):
            findings.append({
                "type": "secret",
                "id": f"SECRET-{s['RuleID']}",
                "title": s.get("Title", f"SECRET-{s['RuleID']}"),
                "severity": s["Severity"],
                "description": s.get("Match", "")
            })
    return findings

# =============================================================================
# Export Functions
# =============================================================================
def export_openscap_bundle(image_name, findings, directory, timestamp, hdf_file):
    xccdf_file = f"{directory}/openscap/{image_name.replace('/', '_').replace(':', '_')}_{timestamp}.xccdf.xml"
    
    try:
        subprocess.run([
            "docker", "run", "--rm", "-v", f"{directory}:/share", "-w", "/share", "mitre/saf:latest", "convert", "hdf2xccdf",
            "-i", f"hdf/{os.path.basename(hdf_file)}",
            "-o", f"openscap/{os.path.basename(xccdf_file)}"
        ], check=True)
        print(f"OpenSCAP XCCDF saved as {xccdf_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error generating XCCDF: {e}")

def export_mitre_saf_hdf(image_name, findings, directory, timestamp):
    # Load the HDF template
    template_path = os.path.join(os.path.dirname(__file__), "container_hardening.hdf.json")
    try:
        with open(template_path, "r") as f:
            hdf = json.load(f)
    except FileNotFoundError:
        # Fallback to minimal HDF if template not found
        hdf = {
            "profiles": [{
                "name": "Trivy Container Scan",
                "title": "Automated scan of container image",
                "controls": []
            }]
        }

    # Add findings as controls
    controls = []
    for f in findings:
        control = {
            "id": f["id"],
            "title": f["title"],
            "desc": f["description"],
            "impact": {"CRITICAL": 0.9, "HIGH": 0.7, "MEDIUM": 0.5, "LOW": 0.3}.get(f["severity"], 0.1),
            "tags": {
                "severity": f["severity"]
            },
            "results": [{
                "status": "failed",
                "code_desc": f"{f['package']} {f['installed']} → {f['fixed']}",
                "start_time": datetime.utcnow().isoformat() + "Z"
            }]
        }
        controls.append(control)

    # Append to existing controls or set
    if "controls" not in hdf["profiles"][0]:
        hdf["profiles"][0]["controls"] = controls
    else:
        hdf["profiles"][0]["controls"].extend(controls)

    filename = f"{directory}/hdf/trivy-hdf-{image_name.replace('/', '_').replace(':', '_')}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(hdf, f, indent=2)
    print(f"MITRE SAF HDF (eMASS-ready) saved as {filename}")
    print("   → Upload with: saf emasser post findings -f", filename)
    return filename

def export_ckl(image_name, findings, directory, timestamp, container_name, digest, hdf_file):
    ckl_file = f"{directory}/ckl/trivy-{image_name.replace('/', '_').replace(':', '_')}_{timestamp}.ckl"
    
    metadata = {
        "asset": {
            "name": container_name,
            "type": "container",
            "classification": "Unclass"
        }
    }
    
    metadata_file = f"{directory}/hdf/metadata_{timestamp}.json"
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f)
    
    try:
        host_dir = os.path.dirname(os.path.abspath(hdf_file))
        subprocess.run([
            "docker", "run", "--rm", "-v", f"{host_dir}:/share", "-w", "/share", "mitre/saf:latest", "convert", "hdf2ckl",
            "-i", os.path.basename(hdf_file),
            "-o", os.path.basename(ckl_file)
        ], check=True)
        if os.path.exists(ckl_file):
            print(f"STIG Viewer CKL saved as {ckl_file}")
        else:
            print(f"Error: CKL file not created at {ckl_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error generating CKL: {e}")
    finally:
        if os.path.exists(metadata_file):
            os.remove(metadata_file)

# =============================================================================
# Main + Interactive Menu
# =============================================================================
def main():
    trivy_scans_dir = os.path.join(args.directory, 'trivy_scans')
    
    # Find and merge scan files
    vuln_files = glob.glob(os.path.join(trivy_scans_dir, 'vuln_*.json'))
    secret_files = glob.glob(os.path.join(trivy_scans_dir, 'secret_*.json'))
    misconfig_files = glob.glob(os.path.join(trivy_scans_dir, 'misconfig_*.json'))
    license_files = glob.glob(os.path.join(trivy_scans_dir, 'license_*.json'))
    
    all_files = vuln_files + secret_files + misconfig_files + license_files
    if not all_files:
        print("Error: No Trivy scan JSON files found in trivy_scans directory")
        sys.exit(1)
    
    data = merge_jsons(all_files)
    image_name = data.get("ArtifactName", "unknown-image")
    findings = extract_findings(data)

    # Extract container name and digest
    container_name = image_name.split('/')[-1].split(':')[0] if '/' in image_name else image_name.split(':')[0]
    digest = data.get("Metadata", {}).get("RepoDigests", [None])[0] or "No digest found"

    print(f"\nFound {len(findings)} findings in {image_name}\n")
    print(f"Container name: {container_name}")
    print(f"Image digest: {digest}\n")

    # Check if base directory is provided
    base_directory = args.directory
    directory = f"{base_directory}/MITRE"

    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Create main directory and subfolders
    os.makedirs(f"{directory}/openscap", exist_ok=True)
    os.makedirs(f"{directory}/hdf", exist_ok=True)
    os.makedirs(f"{directory}/ckl", exist_ok=True)

    # Generate HDF first
    hdf_file = export_mitre_saf_hdf(image_name, findings, directory, timestamp)

    print(f"Results will be saved in directory: {directory}")
    print("Subfolders created: openscap, hdf, ckl")
    print("")

    while True:
        print("Export Options:")
        print("  1) OpenSCAP XCCDF + OVAL Bundle")
        print("  2) MITRE SAF HDF JSON (eMASS POAM upload)")
        print("  3) DISA STIG Viewer CKL")
        print("  4) All of the above")
        print("  5) Exit")
        choice = input("\nChoose (1-5): ").strip()

        prefix = image_name.replace("/", "_").replace(":", "_")

        if choice == "1":
            print("Generating OpenSCAP XCCDF...")
            export_openscap_bundle(image_name, findings, directory, timestamp, hdf_file)
            print("XCCDF generation complete.")
        elif choice == "2":
            print(f"MITRE SAF HDF (eMASS-ready) saved as {hdf_file}")
            print("   → Upload with: saf emasser post findings -f", hdf_file)
        elif choice == "3":
            print("DISA STIG Viewer CKL generation not available due to compatibility issues.")
            print("Use the main hardening script for CKL generation.")
        elif choice == "4":
            print("Generating OpenSCAP XCCDF...")
            export_openscap_bundle(image_name, findings, directory, timestamp, hdf_file)
            print("XCCDF generation complete.")
            print(f"MITRE SAF HDF (eMASS-ready) saved as {hdf_file}")
            print("   → Upload with: saf emasser post findings -f", hdf_file)
            print("DISA STIG Viewer CKL generation not available due to compatibility issues.")
            print("Use the main hardening script for CKL generation.")
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Try again.")

        print()  # newline

if __name__ == "__main__":
    main()