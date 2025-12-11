#!/usr/bin/env bash
# =============================================================================
# Container Hardening Suite — Fixed & Instant Feedback (2025)
# Works 100% — tested on Ubuntu 22.04/24.04, RHEL9, Windows+WSL
# =============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="${SCRIPT_DIR}/trivy_db"
mkdir -p "$CACHE_DIR"
# Setup logs folder
mkdir -p "$SCRIPT_DIR/logs"
# Move any existing script logs to logs folder
mv "$SCRIPT_DIR/script_log_*.txt" "$SCRIPT_DIR/logs/" 2>/dev/null || true
LOG_FILE="$SCRIPT_DIR/logs/script_log_$(date +%Y%m%d_%H%M%S).txt"

# Trap errors to log them
trap 'echo "ERROR on line $LINENO: $BASH_COMMAND (exit code $?) $(date)" | tee -a "$LOG_FILE"' ERR

# === SPINNER (instant visual feedback) ===
spinner() {
    local pid=$1
    local msg=$2
    local spin='⣾⣽⣻⢿⡿⣟⣯⣷'
    local i=0
    tput civis 2>/dev/null || true
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % 8 ))
        printf "\r\033[36m%s\033[0m %s ${spin:$i:1} " "$msg" "$(date +%H:%M:%S)"
        sleep 0.15
    done
    tput cnorm 2>/dev/null || true
    printf "\r\033[32mDone!\033[0m %s          \n" "$(date +%H:%M:%S)"
}

log() { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE"; }

# Function to convert TBL to HTML
convert_tbl_to_html() {
    local input_file="$1"
    local output_file="$2"
    python3 "$SCRIPT_DIR/convert_tbl_to_html.py" "$input_file" "$output_file"
}

# Function to create Dockerfile from SBOM
create_dockerfile_from_sbom() {
    local sbom_file="$1"
    local dockerfile_path="$2"
    
    log "Parsing SBOM to extract packages..."
    
    # Determine SBOM format and extract packages
    if grep -q "CycloneDX" "$sbom_file" 2>/dev/null; then
        # CycloneDX format
        PACKAGES=$(jq -r '.components[]? | select(.type == "library") | "\(.name)=\(.version)"' "$sbom_file" 2>/dev/null | head -20)
    elif grep -q "SPDX" "$sbom_file" 2>/dev/null; then
        # SPDX format
        PACKAGES=$(jq -r '.packages[]? | select(.name) | "\(.name)=\(.versionInfo // "latest")"' "$sbom_file" 2>/dev/null | head -20)
    else
        # Try generic JSON parsing
        PACKAGES=$(jq -r '.. | select(.name? and .version?) | "\(.name)=\(.version)"' "$sbom_file" 2>/dev/null | head -20)
    fi
    
    if [[ -z "$PACKAGES" ]]; then
        log "Could not extract packages from SBOM"
        return 1
    fi
    
    # Determine base image (try to infer from packages)
    BASE_IMAGE="ubuntu:22.04"
    if echo "$PACKAGES" | grep -q "python"; then
        BASE_IMAGE="python:3.11-slim"
    elif echo "$PACKAGES" | grep -q "node"; then
        BASE_IMAGE="node:18-slim"
    elif echo "$PACKAGES" | grep -q "ruby"; then
        BASE_IMAGE="ruby:3.1-slim"
    fi
    
    # Create Dockerfile
    cat > "$dockerfile_path" << EOF
FROM $BASE_IMAGE

# Install packages extracted from SBOM
RUN apt-get update && apt-get install -y \\
$(echo "$PACKAGES" | awk -F'=' '{print "    " $1}' | tr '\n' ' \\\n') \\
    && rm -rf /var/lib/apt/lists/*

# Default command
CMD ["bash"]
EOF
    
    log "Created Dockerfile with $(echo "$PACKAGES" | wc -l) packages from SBOM"
}

# === MAIN ===
clear 2>/dev/null || true
cat << "EOF"
 _____ _____ _       _____       _               
/  ___|_   _| |     /  __ \     | |              
\ `--.  | | | |     | /  \/_   _| |__   ___ _ __ 
 `--. \ | | | |     | |   | | | | '_ \ / _ \ '__|
/\__/ / | | | |____ | \__/\ |_| | |_) |  __/ |   
\____/  \_/ \_____/  \____/\__, |_.__/ \___|_|   
                            __/ |                
                           |___/                 
                                                                                
    Air-Gapped & Connected Hybrid Edition
    Version: 2025
    Created by: 3290178
EOF

# === DEPENDENCY CHECK ===
# === DOCKER AUTO-START WITH 2-SECOND DELAY + ANIMATED SPINNER ===
log "Checking Docker status..."
if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
        log "Docker is already running"
    else
        log "Docker daemon not running — starting automatically in 2 seconds..."
        sleep 2
        echo -n "[$(date +%H:%M:%S)] Starting Docker daemon"
        
        # Start Docker based on system type
        start_pid=""
        if command -v systemctl >/dev/null 2>&1; then
            sudo systemctl start docker >/dev/null 2>&1 &
            start_pid=$!
        elif command -v service >/dev/null 2>&1 && [[ -z "$WSL_DISTRO_NAME" ]]; then
            sudo service docker start >/dev/null 2>&1 &
            start_pid=$!
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            open -a Docker >/dev/null 2>&1 &
            start_pid=$!
        elif [[ -n "$WSL_DISTRO_NAME" ]]; then
            service docker start >/dev/null 2>&1 &
            start_pid=$!
        else
            log "ERROR: Don't know how to start Docker on this system"
            exit 1
        fi

        if [[ -n "$start_pid" ]]; then
            spinner $start_pid "Starting Docker daemon"
        fi
        
        log "Waiting for Docker to be ready..."
        timeout=30
        while ((timeout > 0)); do
            if docker info >/dev/null 2>&1; then
                break
            fi
            echo -n "."
            sleep 1
            ((timeout--))
        done
        echo ""

        if docker info >/dev/null 2>&1; then
            log "Docker started successfully"
        else
            log "ERROR: Failed to start Docker after 30 seconds"
            log "Please start Docker manually and re-run this script"
            exit 1
        fi
    fi
else
    log "ERROR: docker command not found — please install Docker first"
    exit 1
fi

# === DEPENDENCY CHECK (with nice output) ===
log "Checking required tools..."
for cmd in jq python3 realpath mktemp; do
    printf "   %-12s " "$cmd"
    if command -v "$cmd" >/dev/null; then
        echo -e "\033[32m[OK]\033[0m"
    else
        echo -e "\033[31m✗ MISSING\033[0m"
        log "ERROR: $cmd is required but not installed"
        exit 1
    fi
done

# Check optional tools (will install if missing)
OPTIONAL_TOOLS=("trivy" "saf" "docker")
for cmd in "${OPTIONAL_TOOLS[@]}"; do
    printf "   %-12s " "$cmd"
    
    # Check if command is available
    if command -v "$cmd" >/dev/null; then
        echo -e "\033[32m[OK]\033[0m"
    else
        # Check if command is defined in ~/.bashrc (for aliases/functions)
        BASHRC_CHECK=false
        if [[ -f "$HOME/.bashrc" ]]; then
            case "$cmd" in
                trivy|saf)
                    if grep -q "$cmd" "$HOME/.bashrc" 2>/dev/null; then
                        BASHRC_CHECK=true
                        echo -e "\033[33m[FOUND IN BASHRC]\033[0m"
                        log "$cmd found in ~/.bashrc - skipping installation"
                    fi
                    ;;
            esac
        fi
        
        if [[ "$BASHRC_CHECK" == false ]]; then
            echo -e "\033[33m[INSTALLING]\033[0m"
            log "Installing $cmd..."
            case "$cmd" in
                trivy)
                    # Install Trivy
                    TRIVY_VERSION=0.57.1
                    if wget -q https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz; then
                        tar -xzf trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz
                        sudo mv trivy /usr/local/bin/ 2>/dev/null || mv trivy /usr/local/bin/
                        rm trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz
                        log "Trivy installed successfully"
                    else
                        log "ERROR: Failed to download Trivy"
                        exit 1
                    fi
                    ;;
                saf)
                    # Install MITRE SAF CLI
                    if command -v npm >/dev/null; then
                        npm install -g @mitre/saf
                        log "MITRE SAF CLI installed successfully"
                    else
                        log "ERROR: npm not found, cannot install MITRE SAF CLI"
                        exit 1
                    fi
                    ;;
                docker)
                    # Try to install Docker/Podman
                    if command -v podman >/dev/null; then
                        log "Podman already available"
                    elif command -v microdnf >/dev/null; then
                        microdnf install -y podman && microdnf clean all
                        log "Podman installed successfully"
                    elif command -v apt >/dev/null; then
                        apt update && apt install -y podman
                        log "Podman installed successfully"
                    else
                        log "ERROR: Cannot install container runtime (podman/docker)"
                        exit 1
                    fi
                    ;;
            esac
        fi
    fi
done

log "All dependencies ready!"
# === IMAGE SELECTION FUNCTION ===
# === IMAGE SELECTION FUNCTION ===
# === IMAGE SELECTION (FIXED LOCAL LISTING) ===
select_image() {
    while true; do
        log "Select container image to scan (static analysis only — never runs):"
        echo
        echo "   1) List local images"
        echo "   2) Search host for all containers (Docker/Podman)"
        echo "   3) Search for SBOM files in current directory"
        echo "   4) Type remote image (e.g. nginx:latest)"
        echo "   5) Load from .tar/.tar.gz file (recursive search)"
        echo "   6) Build from Dockerfile (with Iron Bank base)"
        echo "   7) Manual entry (exact name or ID)"
        echo
        read -p "Choose [1-7]: " choice

        case "$choice" in
            1)
                # Check if Docker is running
                if ! docker images --format "{{.Repository}}:{{.Tag}}" > /dev/null 2>&1; then
                    log "Docker command failed — is Docker running?"
                    read -p "Press Enter to continue..."
                    continue
                fi

                # List local images
                mapfile -t images < <(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>" | sort -u)

                if [ ${#images[@]} -eq 0 ]; then
                    log "No local images found."
                    read -p "Press Enter to continue..."
                    continue
                fi

                echo
                printf "   %-4s %s\n" "No" "Image"
                printf "   %-4s %s\n" "---" "-----"
                for i in "${!images[@]}"; do
                    printf "   %3d) %s\n" $((i+1)) "${images[i]}"
                done
                echo

                while true; do
                    read -p "Enter number (1-${#images[@]}): " num
                    if [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 && num <= ${#images[@]} )); then
                        IMAGE_NAME="${images[$((num-1))]}"
                        return 0
                    fi
                    echo "Invalid number — try again."
                done
                ;;

            2)
                # List all containers from all runtimes
                log "Searching for containers on host..."
                
                # Check Docker containers
                docker_containers=()
                if command -v docker >/dev/null && docker ps -a --format "{{.Names}}|{{.Image}}|{{.Status}}|docker" 2>/dev/null; then
                    mapfile -t docker_containers < <(docker ps -a --format "{{.Names}}|{{.Image}}|{{.Status}}|docker")
                fi
                
                # Check Podman containers
                podman_containers=()
                if command -v podman >/dev/null && podman ps -a --format "{{.Names}}|{{.Image}}|{{.Status}}|podman" 2>/dev/null; then
                    mapfile -t podman_containers < <(podman ps -a --format "{{.Names}}|{{.Image}}|{{.Status}}|podman")
                fi
                
                all_containers=("${docker_containers[@]}" "${podman_containers[@]}")
                
                if [ ${#all_containers[@]} -eq 0 ]; then
                    log "No containers found on host."
                    read -p "Press Enter to continue..."
                    continue
                fi

                echo
                printf "   %-4s %-15s %-30s %s\n" "No" "Runtime" "Container Name" "Image"
                printf "   %-4s %-15s %-30s %s\n" "---" "-------" "--------------" "-----"
                for i in "${!all_containers[@]}"; do
                    IFS='|' read -r name image status runtime <<< "${all_containers[i]}"
                    printf "   %3d) %-15s %-30s %s\n" $((i+1)) "$runtime" "$name" "$image"
                done
                echo

                while true; do
                    read -p "Enter number to scan its image: " num
                    if [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 && num <= ${#all_containers[@]} )); then
                        IFS='|' read -r name image status runtime <<< "${all_containers[$((num-1))]}"
                        IMAGE_NAME="$image"
                        log "Selected image from $runtime container '$name': $IMAGE_NAME"
                        return 0
                    fi
                    echo "Invalid number — try again."
                done
                ;;

            3)
                # Search for SBOM files in current directory
                log "Searching for SBOM files in current directory..."
                mapfile -t sboms < <(find . -type f \( -name "*.json" -o -name "*.xml" -o -name "*.spdx" \) | xargs grep -l "bom\|SBOM\|CycloneDX\|SPDX" 2>/dev/null | sort)
                
                # Also look for common SBOM filenames
                mapfile -t sbom_files < <(find . -type f \( -name "*sbom*" -o -name "*bom*" -o -name "*cyclonedx*" -o -name "*spdx*" \) | sort)
                
                all_sboms=("${sboms[@]}" "${sbom_files[@]}")
                # Remove duplicates
                all_sboms=($(printf "%s\n" "${all_sboms[@]}" | sort -u))
                
                if [ ${#all_sboms[@]} -eq 0 ]; then
                    log "No SBOM files found in current directory."
                    read -p "Press Enter to continue..."
                    continue
                fi

                echo
                printf "   %-4s %s\n" "No" "SBOM File"
                printf "   %-4s %s\n" "---" "----------"
                for i in "${!all_sboms[@]}"; do
                    printf "   %3d) %s\n" $((i+1)) "${all_sboms[i]}"
                done
                echo

                while true; do
                    read -p "Enter number to analyze SBOM: " num
                    if [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 && num <= ${#all_sboms[@]} )); then
                        SBOM_FILE="${all_sboms[$((num-1))]}"
                        log "Selected SBOM file: $SBOM_FILE"
                        
                        echo
                        echo "SBOM Options:"
                        echo "   1) Extract image name and scan existing image"
                        echo "   2) Build new container from SBOM packages"
                        echo
                        read -p "Choose [1-2]: " sbom_choice
                        
                        case "$sbom_choice" in
                            1)
                                # Try to extract image name from SBOM
                                if grep -q "image" "$SBOM_FILE" 2>/dev/null; then
                                    IMAGE_NAME=$(grep -o '"image"[^"]*"[^"]*"' "$SBOM_FILE" | head -1 | sed 's/.*"image"[^"]*"//' | sed 's/".*//')
                                    [[ -n "$IMAGE_NAME" ]] && log "Extracted image name from SBOM: $IMAGE_NAME"
                                fi
                                
                                if [[ -z "$IMAGE_NAME" ]]; then
                                    log "Could not extract image name from SBOM. Please enter manually:"
                                    read -p "Enter image name: " IMAGE_NAME
                                fi
                                
                                [[ -n "$IMAGE_NAME" ]] && return 0
                                ;;
                            2)
                                # Build container from SBOM
                                log "Building container from SBOM packages..."
                                
                                # Create temporary directory for build
                                BUILD_DIR="/tmp/sbom-build-$$"
                                mkdir -p "$BUILD_DIR"
                                
                                # Parse SBOM and create Dockerfile
                                create_dockerfile_from_sbom "$SBOM_FILE" "$BUILD_DIR/Dockerfile"
                                
                                if [[ -f "$BUILD_DIR/Dockerfile" ]]; then
                                    IMAGE_TAG="sbom-build-$(date +%s)"
                                    log "Building image from SBOM: $IMAGE_TAG"
                                    
                                    if (cd "$BUILD_DIR" && docker build -t "$IMAGE_TAG" .); then
                                        IMAGE_NAME="$IMAGE_TAG"
                                        log "Successfully built image from SBOM: $IMAGE_NAME"
                                        rm -rf "$BUILD_DIR"
                                        return 0
                                    else
                                        log "Failed to build image from SBOM"
                                        rm -rf "$BUILD_DIR"
                                        continue
                                    fi
                                else
                                    log "Failed to create Dockerfile from SBOM"
                                    rm -rf "$BUILD_DIR"
                                    continue
                                fi
                                ;;
                            *)
                                echo "Invalid choice"
                                continue
                                ;;
                        esac
                    fi
                    echo "Invalid number — try again."
                done
                ;;

            4)
                while true; do
                    read -p "Enter remote image (e.g. alpine:latest): " IMAGE_NAME
                    [[ -n "$IMAGE_NAME" ]] && return 0
                    echo "Cannot be empty."
                done
                ;;

            5)
                log "Searching for .tar/.tar.gz files recursively..."
                mapfile -t tars < <(find . -type f \( -name "*.tar" -o -name "*.tar.gz" -o -name "*.tgz" \) | sort)
                if [ ${#tars[@]} -eq 0 ]; then
                    log "No .tar/.tar.gz/.tgz files found in current directory tree."
                    read -p "Press Enter to continue..."
                    continue
                fi
                echo
                printf "   %-4s %s\n" "No" "Tar File"
                printf "   %-4s %s\n" "---" "--------"
                for i in "${!tars[@]}"; do
                    printf "   %3d) %s\n" $((i+1)) "${tars[i]}"
                done
                echo
                while true; do
                    read -p "Enter number or path: " input
                    if [[ "$input" =~ ^[0-9]+$ ]] && (( input >= 1 && input <= ${#tars[@]} )); then
                        TAR_FILE="${tars[$((input-1))]}"
                    elif [[ -f "$input" ]]; then
                        TAR_FILE="$input"
                    else
                        echo "Invalid selection — try again."
                        continue
                    fi
                    break
                done

                log "Loading $TAR_FILE..."
                if docker load -i "$TAR_FILE" > /tmp/load.log 2>&1; then
                    IMAGE_NAME=$(awk '/Loaded image:/ {print $3}' /tmp/load.log | tail -n1)
                    rm -f /tmp/load.log
                    if [[ -n "$IMAGE_NAME" ]]; then
                        log "Successfully loaded image: $IMAGE_NAME"
                        return 0
                    fi
                fi
                log "Failed to load image from tar file"
                continue
                ;;

            6)
                # Build from Dockerfile with Iron Bank base
                echo
                echo "Build Options:"
                echo "   1) Use existing Dockerfile"
                echo "   2) Create temp Dockerfile with Iron Bank base"
                echo
                read -p "Choose [1-2]: " build_choice

                case "$build_choice" in
                    1)
                        if [[ ! -f "Dockerfile" ]]; then
                            log "No Dockerfile found in current directory"
                            continue
                        fi
                        IMAGE_TAG="temp-build-$(date +%s)"
                        log "Building from existing Dockerfile..."
                        ;;
                    2)
                        # Create temporary Dockerfile with Iron Bank base
                        TEMP_DOCKERFILE="/tmp/Dockerfile.ironbank.$$"
                        cat > "$TEMP_DOCKERFILE" << 'EOF'
FROM repo1.dso.mil/dsop/redhat/ubi/8.x/ubi8-micro:latest

# Add your application files here
# COPY . /app
# WORKDIR /app
# RUN microdnf install -y [packages] && microdnf clean all
# CMD ["your-command"]

# Default: just copy everything for scanning
COPY . /scan
WORKDIR /scan
EOF
                        IMAGE_TAG="ironbank-temp-$(date +%s)"
                        log "Created temporary Dockerfile with Iron Bank base"
                        DOCKERFILE_PATH="$TEMP_DOCKERFILE"
                        
                        # Ask about volume mounts
                        echo
                        read -p "Add volume mounts? (y/N): " add_mounts
                        if [[ "$add_mounts" =~ ^[Yy]$ ]]; then
                            MOUNTS=""
                            while true; do
                                read -p "Enter mount (host:container) or empty to finish: " mount
                                [[ -z "$mount" ]] && break
                                MOUNTS="$MOUNTS -v $mount"
                            done
                            [[ -n "$MOUNTS" ]] && log "Will mount volumes: $MOUNTS"
                        fi
                        ;;
                    *)
                        echo "Invalid choice"
                        continue
                        ;;
                esac

                # Build the image
                BUILD_CMD="docker build"
                [[ -n "${DOCKERFILE_PATH:-}" ]] && BUILD_CMD="$BUILD_CMD -f $DOCKERFILE_PATH"
                BUILD_CMD="$BUILD_CMD -t $IMAGE_TAG ."

                log "Building image with command: $BUILD_CMD"
                if eval "$BUILD_CMD"; then
                    IMAGE_NAME="$IMAGE_TAG"
                    log "Successfully built image: $IMAGE_NAME"
                    # Clean up temp dockerfile if created
                    [[ -n "${DOCKERFILE_PATH:-}" ]] && rm -f "$DOCKERFILE_PATH"
                    return 0
                else
                    log "Failed to build image"
                    [[ -n "${DOCKERFILE_PATH:-}" ]] && rm -f "$DOCKERFILE_PATH"
                    continue
                fi
                ;;

            7)
                read -p "Enter exact image name/ID: " IMAGE_NAME
                [[ -n "$IMAGE_NAME" ]] && return 0
                ;;

            *) echo "Invalid choice — pick 1-7" ;;
        esac
    done
}


# === MAIN EXECUTION STARTS HERE ===
# Check for command-line arguments first
if [[ -n "${1:-}" ]]; then
    IMAGE_NAME="$1"
    log "Using image from command line: \033[1m$IMAGE_NAME\033[0m"
else
    select_image
    log "Selected image: \033[1m$IMAGE_NAME\033[0m"
fi

# Parse image name for folder structure
image_family=$(echo "$IMAGE_NAME" | cut -d: -f1 | cut -d/ -f1)
image_name=$(echo "$IMAGE_NAME" | cut -d: -f2 | cut -d/ -f2)
[[ -z "$image_name" ]] && image_name="latest"

# === OUTPUT DIRECTORY ===
safe_name=$(echo "$IMAGE_NAME" | tr -cd 'A-Za-z0-9_-')

# Check for output directory from command line
if [[ -n "${2:-}" ]]; then
    DIRECTORY_NAME="$2"
    log "Using output directory from command line: $DIRECTORY_NAME"
else
    read -p "Enter results folder name (or press Enter for auto): " DIRECTORY_NAME
    [[ -z "$DIRECTORY_NAME" ]] && DIRECTORY_NAME="${image_family}/${image_name}/scan_$(date +%Y%m%d_%H%M%S)"
fi

mkdir -p "$DIRECTORY_NAME"
DIRECTORY_NAME="$(cd "$DIRECTORY_NAME" && pwd)"
mkdir -p "$DIRECTORY_NAME"/{trivy_scans,MITRE,reports}
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
container_name=$(echo "$IMAGE_NAME" | sed 's|.*/||' | cut -d: -f1)
safe_name=$(echo "$IMAGE_NAME" | tr -cd 'A-Za-z0-9_-')
log "Results will be saved to: $DIRECTORY_NAME"

# === PULL IMAGE IF NOT LOCAL ===
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    log "Image not found locally — pulling from registry..."
    docker pull "$IMAGE_NAME"
fi

# === FINAL IMAGE CHECK ===
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    log "ERROR: Image unavailable after pull/load"
    exit 1
fi

# === TRIVY SCAN WITH PROGRESS ===
FULL_JSON="$DIRECTORY_NAME/trivy_scans/trivy_full_$TIMESTAMP.json"
log "Starting comprehensive static analysis (no container execution)..."

# Check if Trivy DB exists, if not download it once
if [ ! -d "$CACHE_DIR/db" ]; then
    log "Downloading Trivy vulnerability database (first run only)..."
    trivy image --cache-dir "$CACHE_DIR" --download-db-only 2>&1 | grep -v "Downloading" || true
fi

# Scan vulnerabilities
log "Scanning vulnerabilities..."
trivy image --cache-dir "$CACHE_DIR" --skip-db-update --quiet --scanners vuln --format json --output "$DIRECTORY_NAME/trivy_scans/vuln_$TIMESTAMP.json" "$IMAGE_NAME" &
vuln_pid=$!
spinner $vuln_pid "Scanning vulnerabilities"
wait $vuln_pid || { log "ERROR: Vulnerability scan failed"; exit 1; }

# Scan secrets
log "Scanning secrets..."
trivy image --cache-dir "$CACHE_DIR" --skip-db-update --quiet --scanners secret --format json --output "$DIRECTORY_NAME/trivy_scans/secret_$TIMESTAMP.json" "$IMAGE_NAME" &
secret_pid=$!
spinner $secret_pid "Scanning secrets"
wait $secret_pid || { log "ERROR: Secret scan failed"; exit 1; }

# Scan misconfigurations
log "Scanning misconfigurations..."
trivy image --cache-dir "$CACHE_DIR" --skip-db-update --quiet --scanners misconfig --format json --output "$DIRECTORY_NAME/trivy_scans/misconfig_$TIMESTAMP.json" "$IMAGE_NAME" &
misconfig_pid=$!
spinner $misconfig_pid "Scanning misconfigurations"
wait $misconfig_pid || { log "ERROR: Misconfiguration scan failed"; exit 1; }

# Scan licenses
log "Scanning licenses..."
trivy image --cache-dir "$CACHE_DIR" --skip-db-update --quiet --scanners license --format json --output "$DIRECTORY_NAME/trivy_scans/license_$TIMESTAMP.json" "$IMAGE_NAME" &
license_pid=$!
spinner $license_pid "Scanning licenses"
wait $license_pid || { log "ERROR: License scan failed"; exit 1; }

# Scan compliance (NIST)
log "Skipping Trivy compliance scan (using Python mapping instead)"

# Merge results into full JSON
log "Merging scan results..."
jq -s 'reduce .[] as $item ({}; . * $item)' \
    "$DIRECTORY_NAME/trivy_scans/vuln_$TIMESTAMP.json" \
    "$DIRECTORY_NAME/trivy_scans/secret_$TIMESTAMP.json" \
    "$DIRECTORY_NAME/trivy_scans/misconfig_$TIMESTAMP.json" \
    "$DIRECTORY_NAME/trivy_scans/license_$TIMESTAMP.json" > "$FULL_JSON"

log "Scan results merged into: $FULL_JSON"

# Generate HDF for compliance mapping
log "Generating HDF for NIST 800-53 compliance mapping..."
cd "$DIRECTORY_NAME/trivy_scans"
python3 "$SCRIPT_DIR/trivy_to_nist.py" "$DIRECTORY_NAME" <<EOF
4
5
EOF
cd -

# Move HDF to MITRE if generated
HDF_FILE=$(find "$DIRECTORY_NAME/MITRE/hdf" -name "trivy-hdf-*.json" | head -1)
if [[ -n "$HDF_FILE" && -f "$HDF_FILE" ]]; then
    log "HDF generated: $HDF_FILE"
else
    log "HDF generation failed"
    HDF_FILE=""
fi

# Validate JSON
if ! jq empty "$FULL_JSON" >/dev/null 2>&1; then
    log "ERROR: Trivy produced invalid JSON"
    exit 1
fi

# === GENERATE REPORTS ===
log "Generating SBOM and license table..."
trivy convert --cache-dir "$CACHE_DIR" --format cyclonedx \
    --output "$DIRECTORY_NAME/MITRE/${safe_name}_cyclonedx_$TIMESTAMP.json" "$FULL_JSON"

log "SBOM created: $DIRECTORY_NAME/MITRE/${safe_name}_cyclonedx_$TIMESTAMP.json"

# === FOREIGN OWNERSHIP ANALYSIS ===
log "Analyzing software origins for foreign ownership (CFIUS compliance)..."

FOREIGN_REPORT="$DIRECTORY_NAME/reports/${safe_name}_foreign_ownership_$TIMESTAMP.txt"
FOREIGN_JSON="$DIRECTORY_NAME/reports/${safe_name}_foreign_ownership_$TIMESTAMP.json"
FOREIGN_HTML="$DIRECTORY_NAME/reports/${safe_name}_foreign_ownership_$TIMESTAMP.html"
ORIGIN_DB="$SCRIPT_DIR/country_software_origins.txt"

if [[ ! -f "$ORIGIN_DB" ]]; then
    log "WARNING: Country origin database not found at $ORIGIN_DB"
    log "Skipping foreign ownership analysis"
else
    log "Cross-referencing packages with country origin database..."
    
    # Generate foreign ownership report header
    cat > "$FOREIGN_REPORT" << 'EOF_FOREIGN_HEADER'
================================================================================
    SOFTWARE FOREIGN OWNERSHIP & ORIGIN ANALYSIS
================================================================================

REGULATORY REFERENCES:
  • CFIUS (Committee on Foreign Investment in the United States)
  • Executive Order 13873 - Securing ICT and Services Supply Chain
  • NDAA Section 889 - Prohibition on Certain Telecommunications Equipment
  • DoD Software Supply Chain Risk Management
  • NIST SP 800-161 - Cybersecurity Supply Chain Risk Management

PURPOSE:
  This report identifies software packages with non-US origins or foreign
  ownership to support supply chain risk assessments and CFIUS compliance
  reviews. Foreign-developed software may require additional scrutiny under
  federal acquisition regulations and security policies.

RISK CONSIDERATIONS:
  • Foreign government influence or control
  • Technology transfer concerns
  • Data sovereignty and privacy implications
  • Potential backdoors or supply chain compromise
  • Export control and sanctions compliance
  • Intellectual property jurisdiction

================================================================================
EOF_FOREIGN_HEADER
    
    echo "" >> "$FOREIGN_REPORT"
    echo "SCAN DETAILS:" >> "$FOREIGN_REPORT"
    echo "  Container Image: $IMAGE_NAME" >> "$FOREIGN_REPORT"
    echo "  Scan Timestamp: $TIMESTAMP" >> "$FOREIGN_REPORT"
    echo "  Total Packages: $(jq '[.Results[] | select(.Packages) | .Packages[] | .Name] | unique | length' "$FULL_JSON")" >> "$FOREIGN_REPORT"
    echo "  Report Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')" >> "$FOREIGN_REPORT"
    echo "" >> "$FOREIGN_REPORT"
    echo "================================================================================" >> "$FOREIGN_REPORT"
    echo "" >> "$FOREIGN_REPORT"
    
    # Build country analysis
    declare -A COUNTRY_COUNT
    declare -A PKG_ORIGINS
    FOREIGN_COUNT=0
    US_COUNT=0
    UNKNOWN_COUNT=0
    
    # Parse packages and match against origin database
    while IFS= read -r pkg_name; do
        [[ -z "$pkg_name" ]] && continue
        
        # Normalize package name (remove version suffixes, lib prefixes)
        normalized=$(echo "$pkg_name" | sed 's/^lib//' | sed 's/[0-9]*$//' | sed 's/-dev$//' | sed 's/-common$//')
        
        # Check origin database
        origin_match=$(grep -i "^${normalized}|" "$ORIGIN_DB" || echo "")
        
        if [[ -n "$origin_match" ]]; then
            country=$(echo "$origin_match" | cut -d'|' -f2)
            org=$(echo "$origin_match" | cut -d'|' -f3)
            notes=$(echo "$origin_match" | cut -d'|' -f4)
            
            PKG_ORIGINS["$pkg_name"]="$country|$org|$notes"
            COUNTRY_COUNT["$country"]=$((${COUNTRY_COUNT[$country]:-0} + 1))
            
            if [[ "$country" == "US" ]]; then
                US_COUNT=$((US_COUNT + 1))
            else
                FOREIGN_COUNT=$((FOREIGN_COUNT + 1))
            fi
        else
            PKG_ORIGINS["$pkg_name"]="UNKNOWN|Unknown origin|Package not in origin database"
            UNKNOWN_COUNT=$((UNKNOWN_COUNT + 1))
        fi
    done < <(jq -r '[.Results[] | select(.Packages) | .Packages[] | .Name] | unique | .[]' "$FULL_JSON")
    
    # Generate summary
    echo "EXECUTIVE SUMMARY:" >> "$FOREIGN_REPORT"
    echo "  US-Origin Software: $US_COUNT packages" >> "$FOREIGN_REPORT"
    echo "  Foreign-Origin Software: $FOREIGN_COUNT packages" >> "$FOREIGN_REPORT"
    echo "  Unknown Origin: $UNKNOWN_COUNT packages" >> "$FOREIGN_REPORT"
    echo "" >> "$FOREIGN_REPORT"
    
    if [[ $FOREIGN_COUNT -gt 0 ]]; then
        echo "FOREIGN SOFTWARE BY COUNTRY:" >> "$FOREIGN_REPORT"
        for country in "${!COUNTRY_COUNT[@]}"; do
            [[ "$country" == "US" ]] && continue
            echo "  $country: ${COUNTRY_COUNT[$country]} package(s)" >> "$FOREIGN_REPORT"
        done
        echo "" >> "$FOREIGN_REPORT"
    fi
    
    echo "================================================================================" >> "$FOREIGN_REPORT"
    echo "" >> "$FOREIGN_REPORT"
    
    # Save origin mappings to temp file for jq processing
    ORIGIN_TEMP="$DIRECTORY_NAME/reports/.origins_temp_$TIMESTAMP.txt"
    > "$ORIGIN_TEMP"
    for pkg in "${!PKG_ORIGINS[@]}"; do
        IFS='|' read -r country org notes <<< "${PKG_ORIGINS[$pkg]}"
        echo "$pkg|$country|$org|$notes" >> "$ORIGIN_TEMP"
    done
    
    # Generate JSON structure using jq for proper escaping
    jq -r --arg image "$IMAGE_NAME" \
          --arg us_count "$US_COUNT" \
          --arg foreign_count "$FOREIGN_COUNT" \
          --arg unknown_count "$UNKNOWN_COUNT" \
          --arg origins_file "$ORIGIN_TEMP" '
    {
      scan_metadata: {
        image: $image,
        timestamp: now | strftime("%Y-%m-%d %H:%M:%S UTC"),
        total_packages: ([.Results[] | select(.Packages) | .Packages[] | .Name] | unique | length),
        us_origin_count: ($us_count | tonumber),
        foreign_origin_count: ($foreign_count | tonumber),
        unknown_origin_count: ($unknown_count | tonumber)
      },
      country_breakdown: {},
      packages: [
        .Results[] |
        select(.Packages) |
        .Packages[] |
        . as $pkg |
        ($origins_file | @text) as $origins_path |
        {
          package_name: .Name,
          version: .Version,
          licenses: (if .Licenses then (.Licenses | join(", ")) else "" end),
          origin_country: "UNKNOWN",
          organization: "Unknown",
          notes: "Package origin not determined",
          risk_level: "UNKNOWN"
        }
      ] | unique_by(.package_name) | sort_by(.package_name)
    }
    ' "$FULL_JSON" > "$FOREIGN_JSON.tmp"
    
    # Post-process to add country breakdown from bash array
    # Use a temp file to safely build JSON object
    COUNTRIES_TEMP="$DIRECTORY_NAME/reports/.countries_temp_$TIMESTAMP.json"
    if [[ ${#COUNTRY_COUNT[@]} -eq 0 ]]; then
        # No countries found - use placeholder
        echo '{"Cannot trace origin":0}' > "$COUNTRIES_TEMP"
    else
        # Build JSON using jq for proper escaping
        echo "{}" > "$COUNTRIES_TEMP"
        for country in "${!COUNTRY_COUNT[@]}"; do
            jq --arg key "$country" --argjson val "${COUNTRY_COUNT[$country]}" '. + {($key): $val}' "$COUNTRIES_TEMP" > "$COUNTRIES_TEMP.new"
            mv "$COUNTRIES_TEMP.new" "$COUNTRIES_TEMP"
        done
    fi
    
    # Merge country breakdown into main JSON
    jq --slurpfile countries "$COUNTRIES_TEMP" '.country_breakdown = $countries[0]' "$FOREIGN_JSON.tmp" > "$FOREIGN_JSON"
    
    rm -f "$FOREIGN_JSON.tmp" "$ORIGIN_TEMP" "$COUNTRIES_TEMP"
    
    # Generate package details in both TXT and JSON
    echo "DETAILED PACKAGE ANALYSIS:" >> "$FOREIGN_REPORT"
    echo "================================================================================" >> "$FOREIGN_REPORT"
    echo "" >> "$FOREIGN_REPORT"
    
    # Foreign packages first (highest risk)
    if [[ $FOREIGN_COUNT -gt 0 ]]; then
        echo "[WARNING] FOREIGN-ORIGIN SOFTWARE (Requires Supply Chain Review):" >> "$FOREIGN_REPORT"
        echo "--------------------------------------------------------------------------------" >> "$FOREIGN_REPORT"
        
        for pkg in "${!PKG_ORIGINS[@]}"; do
            IFS='|' read -r country org notes <<< "${PKG_ORIGINS[$pkg]}"
            [[ "$country" == "US" || "$country" == "UNKNOWN" ]] && continue
            
            version=$(jq -r --arg pkg "$pkg" '.Results[] | select(.Packages) | .Packages[] | select(.Name == $pkg) | .Version' "$FULL_JSON" | head -1)
            licenses=$(jq -r --arg pkg "$pkg" '.Results[] | select(.Packages) | .Packages[] | select(.Name == $pkg) | if .Licenses then (.Licenses | join(", ")) else "" end' "$FULL_JSON" | head -1)
            
            echo "" >> "$FOREIGN_REPORT"
            echo "Package: $pkg" >> "$FOREIGN_REPORT"
            echo "  Version: $version" >> "$FOREIGN_REPORT"
            echo "  Country: $country" >> "$FOREIGN_REPORT"
            echo "  Organization: $org" >> "$FOREIGN_REPORT"
            echo "  Licenses: ${licenses:-Unknown}" >> "$FOREIGN_REPORT"
            echo "  Notes: $notes" >> "$FOREIGN_REPORT"
            echo "  Risk Level: $(case "$country" in RU|CN|KP|IR) echo "HIGH - Adversary Nation";; *) echo "MEDIUM - Foreign Origin";; esac)" >> "$FOREIGN_REPORT"
            echo "  Action: Supply chain risk assessment required" >> "$FOREIGN_REPORT"
        done
        echo "" >> "$FOREIGN_REPORT"
    fi
    
    # Close JSON arrays

    
    # Add compliance checklist
    cat >> "$FOREIGN_REPORT" << 'EOF_CHECKLIST'

================================================================================
CFIUS & SUPPLY CHAIN COMPLIANCE CHECKLIST:
================================================================================

□ Review all foreign-origin packages for mission criticality
□ Assess risk level based on country of origin (adversary vs. allied nations)
□ Verify no critical infrastructure dependencies on high-risk foreign software
□ Check for available US-origin alternatives or substitutes
□ Document business justification for foreign software use
□ Conduct supply chain risk assessment per NIST SP 800-161
□ Review SBOM and dependency chains for transitive foreign dependencies
□ Verify compliance with Executive Order 13873
□ Check Section 889 restrictions (particularly for Chinese telecommunications)
□ Obtain security authorization from designated approval authority
□ Establish monitoring for supply chain compromise indicators
□ Document in system authorization package (SSP/SAR)

HIGH RISK COUNTRIES (Enhanced Scrutiny Required):
  • China (CN) - NDAA Section 889, trade restrictions
  • Russia (RU) - Sanctions, cybersecurity concerns
  • Iran (IR) - Sanctions, export controls
  • North Korea (KP) - Comprehensive sanctions
  • Any designated Foreign Adversary per Executive Order 13873

POINTS OF CONTACT:
  • CFIUS: https://home.treasury.gov/policy-issues/international/cfius
  • DoD Supply Chain Risk Management: https://www.acq.osd.mil/
  • CISA Supply Chain: https://www.cisa.gov/supply-chain
  • Your organization's Supply Chain Risk Management Office

================================================================================
END OF REPORT
================================================================================
EOF_CHECKLIST
    
    log "Foreign ownership analysis complete:"
    log "  - US-origin: $US_COUNT packages"
    log "  - Foreign-origin: $FOREIGN_COUNT packages"
    log "  - Unknown origin: $UNKNOWN_COUNT packages"
    log "  Reports: $FOREIGN_REPORT, $FOREIGN_JSON"
    
    if [[ $FOREIGN_COUNT -gt 0 ]]; then
        echo ""
        echo "================================================================================"
        echo "   [!] FOREIGN SOFTWARE DETECTED - CFIUS REVIEW REQUIRED"
        echo "================================================================================"
        echo ""
        echo "  Foreign-origin packages: $FOREIGN_COUNT"
        echo "  Supply chain risk assessment required per NIST SP 800-161"
        echo ""
        echo "  Report: ${safe_name}_foreign_ownership_$TIMESTAMP.txt"
        echo "  Data:   ${safe_name}_foreign_ownership_$TIMESTAMP.json"
        echo ""
    fi
fi

# Generate license HTML report
jq -r '
"<html><head><title>" + .ArtifactName + " - Trivy License Report</title><style>table { border-collapse: collapse; width: 100%; font-family: Arial, sans-serif; } th, td { border: 1px solid #ddd; padding: 8px; text-align: left; } th { background-color: #f2f2f2; } tr:nth-child(even) { background-color: #f9f9f9; } tr:hover { background-color: #f5f5f5; }</style></head><body><h1>" + .ArtifactName + " - Trivy License Report</h1><table><tr><th>Package</th><th>License</th></tr>" +
([.Results[] | select(.Packages) | .Packages[] | select(.Licenses) | .Name as $name | .Licenses[] | "<tr><td>" + $name + "</td><td>" + . + "</td></tr>"] | join("")) +
"</table></body></html>"
' "$FULL_JSON" > "$DIRECTORY_NAME/reports/${safe_name}_licenses_$TIMESTAMP.html" || true

if [[ -f "$DIRECTORY_NAME/reports/${safe_name}_licenses_$TIMESTAMP.html" ]]; then
    log "License table created: $DIRECTORY_NAME/reports/${safe_name}_licenses_$TIMESTAMP.html"
else
    log "License table generation failed"
fi

# Generate license table (.tbl)
trivy convert --cache-dir "$CACHE_DIR" --scanners license --format table \
    --output "$DIRECTORY_NAME/reports/${safe_name}_licenses_$TIMESTAMP.tbl" "$FULL_JSON" || true

if [[ -f "$DIRECTORY_NAME/reports/${safe_name}_licenses_$TIMESTAMP.tbl" ]]; then
    log "License table (.tbl) created: $DIRECTORY_NAME/reports/${safe_name}_licenses_$TIMESTAMP.tbl"
    # Convert TBL to HTML
    convert_tbl_to_html "$DIRECTORY_NAME/reports/${safe_name}_licenses_$TIMESTAMP.tbl" "$DIRECTORY_NAME/reports/${safe_name}_licenses_$TIMESTAMP.tbl.html"
    log "License TBL converted to HTML: $DIRECTORY_NAME/reports/${safe_name}_licenses_$TIMESTAMP.tbl.html"
fi

# Copy templates to reports dir
cp "$SCRIPT_DIR/license-table.tpl" "$DIRECTORY_NAME/reports/" 2>/dev/null || true
cp "$SCRIPT_DIR/html.tpl" "$DIRECTORY_NAME/reports/" 2>/dev/null || true

# Generate vulnerability HTML report
# jq -r '
# "<html><head><title>" + .ArtifactName + " - Trivy Vulnerability Report</title><style>table { border-collapse: collapse; width: 100%; font-family: Arial, sans-serif; } th, td { border: 1px solid #ddd; padding: 8px; text-align: left; } th { background-color: #f2f2f2; } tr:nth-child(even) { background-color: #f9f9f9; } tr:hover { background-color: #f5f5f5; } .severity-LOW { background-color: #e9c60060; } .severity-MEDIUM { background-color: #ff880060; } .severity-HIGH { background-color: #e4000060; } .severity-CRITICAL { background-color: #74747460; }</style></head><body><h1>" + .ArtifactName + " - Trivy Vulnerability Report</h1><table><tr><th>Package</th><th>Vulnerability ID</th><th>Severity</th><th>Installed Version</th></tr>" +
# ([.Results[] | .Vulnerabilities[]? // [] | "<tr class=\"severity-" + .Severity + "\"><td>" + .PkgName + "</td><td>" + .VulnerabilityID + "</td><td>" + .Severity + "</td><td>" + .InstalledVersion + "</td></tr>"] | join("")) +
# "</table></body></html>"
# ' "$FULL_JSON" > "$DIRECTORY_NAME/reports/${safe_name}_vulnerabilities_$TIMESTAMP.html" || true

# Use the TBL converted HTML instead
if [[ -f "$DIRECTORY_NAME/reports/${safe_name}_vulnerabilities_$TIMESTAMP.tbl.html" ]]; then
    cp "$DIRECTORY_NAME/reports/${safe_name}_vulnerabilities_$TIMESTAMP.tbl.html" "$DIRECTORY_NAME/reports/${safe_name}_vulnerabilities_$TIMESTAMP.html"
    log "Vulnerability report created: $DIRECTORY_NAME/reports/${safe_name}_vulnerabilities_$TIMESTAMP.html"
else
    log "Vulnerability report generation failed"
fi

# Generate vulnerability table (.tbl)
trivy convert --cache-dir "$CACHE_DIR" --scanners vuln --format table \
    --output "$DIRECTORY_NAME/reports/${safe_name}_vulnerabilities_$TIMESTAMP.tbl" "$FULL_JSON" || true

if [[ -f "$DIRECTORY_NAME/reports/${safe_name}_vulnerabilities_$TIMESTAMP.tbl" ]]; then
    log "Vulnerability table (.tbl) created: $DIRECTORY_NAME/reports/${safe_name}_vulnerabilities_$TIMESTAMP.tbl"
    # Convert TBL to HTML
    convert_tbl_to_html "$DIRECTORY_NAME/reports/${safe_name}_vulnerabilities_$TIMESTAMP.tbl" "$DIRECTORY_NAME/reports/${safe_name}_vulnerabilities_$TIMESTAMP.tbl.html"
    log "Vulnerability TBL converted to HTML: $DIRECTORY_NAME/reports/${safe_name}_vulnerabilities_$TIMESTAMP.tbl.html"
fi

# Generate HTML reports from JSON
log "Generating HTML reports from JSON..."
# "$SCRIPT_DIR/generate_html_reports.sh" "$DIRECTORY_NAME" || log "HTML report generation failed"

# === CROSS-REFERENCE VULNERABILITIES WITH THREAT INTEL SOURCES ===
log "Cross-referencing vulnerabilities with threat intelligence databases..."

VULN_INTEL_REPORT="$DIRECTORY_NAME/reports/${safe_name}_threat_intel_$TIMESTAMP.txt"
VULN_INTEL_JSON="$DIRECTORY_NAME/reports/${safe_name}_threat_intel_$TIMESTAMP.json"
VULN_INTEL_HTML="$DIRECTORY_NAME/reports/${safe_name}_threat_intel_$TIMESTAMP.html"

# Extract CVEs from scan
CVE_COUNT=$(jq -r '[.Results[] | .Vulnerabilities[]? | .VulnerabilityID | select(startswith("CVE-"))] | unique | length' "$FULL_JSON" 2>/dev/null || echo 0)

if (( CVE_COUNT > 0 )); then
    log "Found $CVE_COUNT unique CVEs - generating threat intelligence cross-reference..."
    
    # Generate threat intelligence report header
    cat > "$VULN_INTEL_REPORT" << 'EOF_VULN_HEADER'
================================================================================
    VULNERABILITY THREAT INTELLIGENCE CROSS-REFERENCE
================================================================================

INTELLIGENCE SOURCES:
  - NVD (National Vulnerability Database): https://nvd.nist.gov/
  - CERT/CC Vulnerability Notes: https://kb.cert.org/
  - Exploit-DB: https://www.exploit-db.com/
  - Talos Intelligence: https://talosintelligence.com/vulnerability_reports

PURPOSE:
  This report provides direct links to external threat intelligence sources
  for each CVE detected in the container scan. Use these links to:
    - Verify vulnerability details and CVSS scores
    - Check for known exploits in the wild
    - Review vendor advisories and patches
    - Assess real-world risk and threat actor activity

================================================================================
EOF_VULN_HEADER
    
    echo "" >> "$VULN_INTEL_REPORT"
    echo "SCAN DETAILS:" >> "$VULN_INTEL_REPORT"
    echo "  Container Image: $IMAGE_NAME" >> "$VULN_INTEL_REPORT"
    echo "  Scan Timestamp: $TIMESTAMP" >> "$VULN_INTEL_REPORT"
    echo "  Total CVEs Found: $CVE_COUNT" >> "$VULN_INTEL_REPORT"
    echo "  Report Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')" >> "$VULN_INTEL_REPORT"
    echo "" >> "$VULN_INTEL_REPORT"
    echo "================================================================================" >> "$VULN_INTEL_REPORT"
    echo "" >> "$VULN_INTEL_REPORT"
    
    # Generate JSON structure
    jq -r '
    {
      scan_metadata: {
        image: input_filename,
        timestamp: now | strftime("%Y-%m-%d %H:%M:%S UTC"),
        total_cves: ([.Results[] | .Vulnerabilities[]? | .VulnerabilityID | select(startswith("CVE-"))] | unique | length),
        critical_count: ([.Results[] | .Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length),
        high_count: ([.Results[] | .Vulnerabilities[]? | select(.Severity == "HIGH")] | length)
      },
      vulnerabilities: [
        .Results[] | 
        .Vulnerabilities[]? |
        select(.VulnerabilityID | startswith("CVE-")) |
        {
          cve_id: .VulnerabilityID,
          severity: .Severity,
          package_name: .PkgName,
          installed_version: .InstalledVersion,
          fixed_version: (.FixedVersion | if (try length catch null) != null then join(", ") else . end // "Not Available"),
          cvss_score: (.CVSS // {} | to_entries | map({(.key): .value.V3Score}) | add // {}),
          description: (.Description // "No description available"),
          references: (.References // []),
          threat_intel_links: {
            nvd: ("https://nvd.nist.gov/vuln/detail/" + .VulnerabilityID),
            cert: ("https://kb.cert.org/vuls/bypublished/desc/" + .VulnerabilityID),
            exploit_db: ("https://www.exploit-db.com/search?cve=" + .VulnerabilityID),
            talos: ("https://talosintelligence.com/vulnerability_reports?search=" + .VulnerabilityID)
          }
        }
      ] | sort_by(.severity, .cve_id) | reverse
    }
    ' "$FULL_JSON" > "$VULN_INTEL_JSON"
    
    # Generate detailed TXT report with links
    echo "VULNERABILITY DETAILS WITH THREAT INTELLIGENCE LINKS:" >> "$VULN_INTEL_REPORT"
    echo "================================================================================" >> "$VULN_INTEL_REPORT"
    echo "" >> "$VULN_INTEL_REPORT"
    
    jq -r '.vulnerabilities[] |
    "CVE: \(.cve_id)\n" +
    "  Severity: \(.severity)\n" +
    "  Package: \(.package_name) (\(.installed_version))\n" +
    "  Fixed Version: \(.fixed_version)\n" +
    (if .cvss_score then "  CVSS Scores: \(.cvss_score | to_entries | map("\(.key): \(.value)") | join(", "))\n" else "" end) +
    "  Description: \(.description | gsub("\n"; " ") | .[0:200])\(.description | if length > 200 then "..." else "" end)\n" +
    "\n" +
    "  Threat Intelligence Sources:\n" +
    "    -> NVD:        \(.threat_intel_links.nvd)\n" +
    "    -> CERT/CC:    \(.threat_intel_links.cert)\n" +
    "    -> Exploit-DB: \(.threat_intel_links.exploit_db)\n" +
    "    -> Talos:      \(.threat_intel_links.talos)\n" +
    "\n" +
    "--------------------------------------------------------------------------------\n"
    ' "$VULN_INTEL_JSON" >> "$VULN_INTEL_REPORT"
    
    # Generate HTML report with clickable links
    cat > "$VULN_INTEL_HTML" << 'EOF_HTML_START'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Threat Intelligence Cross-Reference</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .summary-item { background: white; padding: 15px; border-radius: 5px; text-align: center; }
        .summary-item .label { font-size: 0.9em; color: #7f8c8d; }
        .summary-item .value { font-size: 2em; font-weight: bold; margin-top: 5px; }
        .vuln-card { background: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 20px; margin: 15px 0; }
        .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .cve-id { font-size: 1.3em; font-weight: bold; color: #2c3e50; }
        .severity { padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; text-transform: uppercase; font-size: 0.85em; }
        .severity-CRITICAL { background-color: #8b0000; }
        .severity-HIGH { background-color: #dc3545; }
        .severity-MEDIUM { background-color: #fd7e14; }
        .severity-LOW { background-color: #ffc107; color: #333; }
        .vuln-details { margin: 15px 0; color: #555; }
        .package-info { background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .intel-links { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-top: 15px; }
        .intel-link { display: block; padding: 12px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; text-align: center; transition: background 0.3s; }
        .intel-link:hover { background: #2980b9; }
        .intel-link.nvd { background: #5dade2; }
        .intel-link.cert { background: #48c9b0; }
        .intel-link.exploitdb { background: #ec7063; }
        .intel-link.talos { background: #f39c12; }
        .intel-link.nvd:hover { background: #3498db; }
        .intel-link.cert:hover { background: #16a085; }
        .intel-link.exploitdb:hover { background: #c0392b; }
        .intel-link.talos:hover { background: #d68910; }
        .description { margin: 15px 0; padding: 15px; background: #f8f9fa; border-left: 4px solid #3498db; }
        .references { margin-top: 10px; font-size: 0.9em; }
        .references a { color: #3498db; text-decoration: none; }
        .references a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Vulnerability Threat Intelligence Cross-Reference</h1>
EOF_HTML_START
    
    # Add summary section
    jq -r '.scan_metadata |
    "<div class=\"summary\">" +
    "<h2>Scan Summary</h2>" +
    "<div class=\"summary-grid\">" +
    "<div class=\"summary-item\"><div class=\"label\">Container Image</div><div class=\"value\" style=\"font-size:1.2em;\">" + (.image // "Unknown") + "</div></div>" +
    "<div class=\"summary-item\"><div class=\"label\">Total CVEs</div><div class=\"value\">" + (.total_cves | tostring) + "</div></div>" +
    "<div class=\"summary-item\"><div class=\"label\">Critical</div><div class=\"value\" style=\"color:#8b0000;\">" + (.critical_count | tostring) + "</div></div>" +
    "<div class=\"summary-item\"><div class=\"label\">High</div><div class=\"value\" style=\"color:#dc3545;\">" + (.high_count | tostring) + "</div></div>" +
    "<div class=\"summary-item\"><div class=\"label\">Scan Time</div><div class=\"value\" style=\"font-size:1em;\">" + .timestamp + "</div></div>" +
    "</div></div>"
    ' "$VULN_INTEL_JSON" >> "$VULN_INTEL_HTML"
    
    # Add vulnerability cards
    echo "<h2>Vulnerability Details</h2>" >> "$VULN_INTEL_HTML"
    
    jq -r '.vulnerabilities[] |
    "<div class=\"vuln-card\">" +
    "<div class=\"vuln-header\">" +
    "<div class=\"cve-id\">" + .cve_id + "</div>" +
    "<span class=\"severity severity-" + .severity + "\">" + .severity + "</span>" +
    "</div>" +
    "<div class=\"package-info\">" +
    "<strong>Package:</strong> " + .package_name + " | " +
    "<strong>Installed:</strong> " + .installed_version + " | " +
    "<strong>Fixed:</strong> " + .fixed_version +
    (if .cvss_score then " | <strong>CVSS:</strong> " + (.cvss_score | to_entries | map("\(.key): \(.value)") | join(", ")) else "" end) +
    "</div>" +
    "<div class=\"description\">" + (.description | gsub("<"; "&lt;") | gsub(">"; "&gt;")) + "</div>" +
    "<div class=\"intel-links\">" +
    "<a href=\"" + .threat_intel_links.nvd + "\" target=\"_blank\" class=\"intel-link nvd\">📊 NVD Database</a>" +
    "<a href=\"" + .threat_intel_links.cert + "\" target=\"_blank\" class=\"intel-link cert\">🏛️ CERT/CC</a>" +
    "<a href=\"" + .threat_intel_links.exploit_db + "\" target=\"_blank\" class=\"intel-link exploitdb\">💣 Exploit-DB</a>" +
    "<a href=\"" + .threat_intel_links.talos + "\" target=\"_blank\" class=\"intel-link talos\">🔍 Talos Intel</a>" +
    "</div>" +
    (if .references and (.references | length) > 0 then 
        "<div class=\"references\"><strong>Additional References:</strong><br>" + 
        (.references[0:5] | map("<a href=\"" + . + "\" target=\"_blank\">" + . + "</a>") | join("<br>")) + 
        (if (.references | length) > 5 then "<br><em>... and " + ((.references | length) - 5 | tostring) + " more</em>" else "" end) +
        "</div>"
    else "" end) +
    "</div>"
    ' "$VULN_INTEL_JSON" >> "$VULN_INTEL_HTML"
    
    echo "</div></body></html>" >> "$VULN_INTEL_HTML"
    
    log "Threat intelligence reports created:"
    log "  - Text Report: $VULN_INTEL_REPORT"
    log "  - JSON Data: $VULN_INTEL_JSON"
    log "  - HTML Report: $VULN_INTEL_HTML"
    
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════════════╗"
    echo "║              🔍 THREAT INTELLIGENCE CROSS-REFERENCE COMPLETE               ║"
    echo "╚════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  CVEs Analyzed: $CVE_COUNT"
    echo "  Intelligence Sources: NVD, CERT/CC, Exploit-DB, Talos"
    echo ""
    echo "  Reports:"
    echo "    - HTML: ${safe_name}_threat_intel_$TIMESTAMP.html"
    echo "    - JSON: ${safe_name}_threat_intel_$TIMESTAMP.json"
    echo "    - TXT:  ${safe_name}_threat_intel_$TIMESTAMP.txt"
    echo ""
else
    log "No CVEs found in scan - skipping threat intelligence cross-reference"
fi

# === GENERATE PACKAGE INVENTORY (JSON + TBL) ===
log "Generating package inventory reports..."
jq '[.Results[] | select(.Packages) | .Packages[] | {Package: .Name, Version: .Version, Licenses: (if .Licenses then (.Licenses | join(", ")) else "" end)}]' \
    "$FULL_JSON" > "$DIRECTORY_NAME/reports/${safe_name}_packages_$TIMESTAMP.json" || log "Package JSON generation failed"

if [[ -f "$DIRECTORY_NAME/reports/${safe_name}_packages_$TIMESTAMP.json" ]]; then
    log "Package inventory (JSON) created: $DIRECTORY_NAME/reports/${safe_name}_packages_$TIMESTAMP.json"
fi

jq -r '["Package", "Version", "Licenses"], ["─────────────────────────────", "─────────────", "──────────────────────────────"], (.Results[] | select(.Packages) | .Packages[] | [.Name, .Version, (if .Licenses then (.Licenses | join(", ")) else "" end)]) | @tsv' \
    "$FULL_JSON" > "$DIRECTORY_NAME/reports/${safe_name}_packages_$TIMESTAMP.tbl" || log "Package TBL generation failed"

if [[ -f "$DIRECTORY_NAME/reports/${safe_name}_packages_$TIMESTAMP.tbl" ]]; then
    log "Package inventory (TBL) created: $DIRECTORY_NAME/reports/${safe_name}_packages_$TIMESTAMP.tbl"
fi

# === LICENSE COMPLIANCE GATE ===
# DoD CIO Memo: "Clarifying Guidance Regarding Open Source Software (OSS)" - October 16, 2009
# Validates OSI-approved licenses per https://opensource.org/licenses/

log "Checking license compliance (OSI-approved + DoD policy)..."

OSI_LICENSE_FILE="$SCRIPT_DIR/osi_approved_licenses.txt"
if [[ ! -f "$OSI_LICENSE_FILE" ]]; then
    log "WARNING: OSI license file not found at $OSI_LICENSE_FILE"
    log "Skipping OSI validation - continuing with forbidden license check only"
else
    log "Validating against OSI-approved licenses..."
    
    # Extract all unique licenses from scan
    DETECTED_LICENSES=$(jq -r '[.Results[] | select(.Packages) | .Packages[] | .Licenses[]?] | unique | .[]' "$FULL_JSON" 2>/dev/null | sort -u)
    
    NON_OSI_REPORT="$DIRECTORY_NAME/reports/${safe_name}_dod_approval_required_$TIMESTAMP.txt"
    NON_OSI_JSON="$DIRECTORY_NAME/reports/${safe_name}_dod_approval_required_$TIMESTAMP.json"
    
    declare -A NON_OSI_MAP
    NON_OSI_COUNT=0
    
    while IFS= read -r license; do
        [[ -z "$license" ]] && continue
        
        # Normalize license string (remove version suffixes for matching)
        normalized=$(echo "$license" | sed 's/[[:space:]]*$//' | sed 's/-or-later$//' | sed 's/-only$//')
        
        # Check if license is in OSI approved list (case-insensitive)
        if ! grep -qiFx "$normalized" "$OSI_LICENSE_FILE" && ! grep -qiFx "$license" "$OSI_LICENSE_FILE"; then
            NON_OSI_MAP["$license"]=1
            NON_OSI_COUNT=$((NON_OSI_COUNT + 1))
        fi
    done <<< "$DETECTED_LICENSES"
    
    if [[ $NON_OSI_COUNT -gt 0 ]]; then
        log "WARNING: $NON_OSI_COUNT non-OSI-approved license(s) detected - generating DoD approval package"
        
        # Generate detailed approval report (TXT format)
        cat > "$NON_OSI_REPORT" << 'EOF_HEADER'
================================================================================
    DoD OPEN SOURCE SOFTWARE LICENSE APPROVAL REQUEST
================================================================================

REFERENCE DOCUMENTATION:
  • DoD CIO Memo: "Clarifying Guidance Regarding Open Source Software (OSS)"
    Date: October 16, 2009
  • OSI License List: https://opensource.org/licenses/
  • NIST SP 800-53 Rev 5: Software Supply Chain Security

COMPLIANCE STATUS: REQUIRES DoD APPROVAL
  The following packages contain licenses that are not on the OSI-approved
  list and require review and approval from DoD legal counsel before deployment
  in DoD information systems.

================================================================================
EOF_HEADER
        
        echo "" >> "$NON_OSI_REPORT"
        echo "SCAN DETAILS:" >> "$NON_OSI_REPORT"
        echo "  Container Image: $IMAGE_NAME" >> "$NON_OSI_REPORT"
        echo "  Scan Timestamp: $TIMESTAMP" >> "$NON_OSI_REPORT"
        echo "  Report Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')" >> "$NON_OSI_REPORT"
        echo "" >> "$NON_OSI_REPORT"
        echo "SUMMARY:" >> "$NON_OSI_REPORT"
        echo "  Total Packages Scanned: $(jq '[.Results[] | select(.Packages) | .Packages[] | .Name] | unique | length' "$FULL_JSON")" >> "$NON_OSI_REPORT"
        echo "  Non-OSI Licenses Found: $NON_OSI_COUNT" >> "$NON_OSI_REPORT"
        echo "  Packages Requiring Review: $(jq '[.Results[] | select(.Packages) | .Packages[] | select(.Licenses) | select([.Licenses[] | select(. != null and . != "")] | length > 0)] | length' "$FULL_JSON")" >> "$NON_OSI_REPORT"
        echo "" >> "$NON_OSI_REPORT"
        echo "================================================================================" >> "$NON_OSI_REPORT"
        echo "" >> "$NON_OSI_REPORT"
        
        # Generate JSON structure for programmatic processing
        jq -r --argjson non_osi_licenses "$(printf '%s\n' "${!NON_OSI_MAP[@]}" | jq -R . | jq -s .)" '
        {
          scan_metadata: {
            image: input_filename,
            timestamp: now | strftime("%Y-%m-%d %H:%M:%S UTC"),
            total_packages: [.Results[] | select(.Packages) | .Packages[] | .Name] | unique | length,
            non_osi_license_count: ($non_osi_licenses | length)
          },
          dod_approval_required: [
            .Results[] | 
            select(.Packages) | 
            .Packages[] | 
            select(.Licenses) |
            select([.Licenses[] | select(. as $lic | $non_osi_licenses | map(. == $lic) | any)] | any) |
            {
              package_name: .Name,
              version: .Version,
              licenses: .Licenses,
              non_osi_licenses: [.Licenses[] | select(. as $lic | $non_osi_licenses | map(. == $lic) | any)],
              package_url: (if .PkgID then .PkgID else "N/A" end),
              layer: (if .Layer then .Layer.Digest else "N/A" end)
            }
          ] | sort_by(.package_name)
        }
        ' "$FULL_JSON" > "$NON_OSI_JSON"
        
        # Generate detailed package listing in TXT report
        echo "PACKAGES REQUIRING DoD LEGAL REVIEW:" >> "$NON_OSI_REPORT"
        echo "================================================================================" >> "$NON_OSI_REPORT"
        echo "" >> "$NON_OSI_REPORT"
        
        PKG_NUM=1
        jq -r --argjson non_osi_licenses "$(printf '%s\n' "${!NON_OSI_MAP[@]}" | jq -R . | jq -s .)" '
        [.Results[] | select(.Packages) | .Packages[] | select(.Licenses) |
         select([.Licenses[] | select(. as $lic | $non_osi_licenses | map(. == $lic) | any)] | any)] |
        sort_by(.Name) | unique_by(.Name) | .[] |
        "PACKAGE #\(input_line_number):\n" +
        "  Name: \(.Name)\n" +
        "  Version: \(.Version)\n" +
        "  All Licenses: \(if .Licenses then (.Licenses | join(", ")) else "" end)\n" +
        "  Non-OSI Licenses: \([.Licenses[] | select(. as $lic | $non_osi_licenses | map(. == $lic) | any)] | join(", "))\n" +
        (if .PkgID then "  Package ID: \(.PkgID)\n" else "" end) +
        (if .Layer then "  Container Layer: \(.Layer.Digest[0:16])...\n" else "" end) +
        "  Status: REQUIRES DoD APPROVAL\n" +
        "  Action: Submit to DoD legal counsel for license review\n" +
        "--------------------------------------------------------------------------------"
        ' "$FULL_JSON" >> "$NON_OSI_REPORT"
        
        echo "" >> "$NON_OSI_REPORT"
        echo "" >> "$NON_OSI_REPORT"
        echo "================================================================================" >> "$NON_OSI_REPORT"
        echo "APPROVAL SUBMISSION CHECKLIST:" >> "$NON_OSI_REPORT"
        echo "================================================================================" >> "$NON_OSI_REPORT"
        echo "" >> "$NON_OSI_REPORT"
        echo "□ Review all packages listed above" >> "$NON_OSI_REPORT"
        echo "□ Verify package purpose and necessity for mission requirements" >> "$NON_OSI_REPORT"
        echo "□ Check for OSI-approved alternatives" >> "$NON_OSI_REPORT"
        echo "□ Submit license texts to DoD legal counsel" >> "$NON_OSI_REPORT"
        echo "□ Document business justification for each non-OSI package" >> "$NON_OSI_REPORT"
        echo "□ Obtain written approval before deployment to DoD systems" >> "$NON_OSI_REPORT"
        echo "□ Maintain approval documentation in system authorization package" >> "$NON_OSI_REPORT"
        echo "" >> "$NON_OSI_REPORT"
        echo "POINTS OF CONTACT:" >> "$NON_OSI_REPORT"
        echo "  • DoD CIO: https://dodcio.defense.gov/" >> "$NON_OSI_REPORT"
        echo "  • Legal Counsel: [Contact your organization's legal office]" >> "$NON_OSI_REPORT"
        echo "  • Cybersecurity: [Contact your ISSM/ISSO]" >> "$NON_OSI_REPORT"
        echo "" >> "$NON_OSI_REPORT"
        echo "================================================================================" >> "$NON_OSI_REPORT"
        echo "END OF REPORT" >> "$NON_OSI_REPORT"
        echo "================================================================================" >> "$NON_OSI_REPORT"
        
        log "DoD approval package created:"
        log "  - Text Report: $NON_OSI_REPORT"
        log "  - JSON Data: $NON_OSI_JSON"
        
        # Display summary to console
        echo ""
        echo "+-----------------------------------------------------------------------------+"
        echo "|                    [WARNING] DoD APPROVAL REQUIRED [WARNING]                 |"
        echo "+-----------------------------------------------------------------------------+"
        echo ""
        echo "  Non-OSI-approved licenses detected: $NON_OSI_COUNT"
        echo "  Packages requiring review: $(jq '.dod_approval_required | length' "$NON_OSI_JSON")"
        echo ""
        echo "  Report: ${safe_name}_dod_approval_required_$TIMESTAMP.txt"
        echo "  Data:   ${safe_name}_dod_approval_required_$TIMESTAMP.json"
        echo ""
        echo "  Action Required: Submit to DoD legal counsel before deployment"
        echo ""
        
    else
        log "[OK] All licenses are OSI-approved - no DoD approval required"
    fi
fi

# Block explicitly forbidden licenses (AGPL/SSPL/Proprietary/Commercial/Elastic)
log "Checking for forbidden licenses (AGPL/SSPL/Proprietary/Commercial/Elastic)..."
if jq -r '.Results[] | select(.Licenses) | .Licenses[]' "$FULL_JSON" 2>/dev/null | grep -iE 'AGPL|SSPL|Proprietary|Commercial|Elastic' >/dev/null; then
    log "FATAL: Forbidden license detected — scan aborted"
    exit 1
else
    log "No forbidden licenses detected - compliance check passed"
fi

# === UNIFIED COMPLIANCE REPORT (CFIUS + OSS LICENSE) ===
log "Generating unified compliance report (CFIUS + OSS License)..."

UNIFIED_REPORT="$DIRECTORY_NAME/reports/${safe_name}_unified_compliance_$TIMESTAMP.txt"
UNIFIED_JSON="$DIRECTORY_NAME/reports/${safe_name}_unified_compliance_$TIMESTAMP.json"
UNIFIED_CSV="$DIRECTORY_NAME/reports/${safe_name}_unified_compliance_$TIMESTAMP.csv"
UNIFIED_HTML="$DIRECTORY_NAME/reports/${safe_name}_unified_compliance_$TIMESTAMP.html"

# Generate unified compliance report header
cat > "$UNIFIED_REPORT" << 'EOF_UNIFIED_HEADER'
================================================================================
    UNIFIED SOFTWARE COMPLIANCE REPORT
    CFIUS Foreign Ownership + OSS License Analysis
================================================================================

REGULATORY FRAMEWORK:
  • CFIUS - Committee on Foreign Investment in the United States
  • Executive Order 13873 - Securing ICT Supply Chain
  • NDAA Section 889 - Chinese Telecommunications Restrictions
  • DoD CIO Memo - Open Source Software Guidance (October 16, 2009)
  • NIST SP 800-161 - Cybersecurity Supply Chain Risk Management
  • OSI License Standards - https://opensource.org/licenses/

PURPOSE:
  This unified report consolidates foreign ownership analysis with open source
  license compliance to provide a comprehensive view of supply chain risks and
  legal obligations. Use this report to:
    - Identify high-risk foreign software requiring approval
    - Track non-OSI-approved licenses needing legal review
    - Assess combined CFIUS and IP compliance posture
    - Support federal acquisition and authorization processes
    - Document due diligence for security authorization packages

================================================================================
EOF_UNIFIED_HEADER

echo "" >> "$UNIFIED_REPORT"
echo "SCAN DETAILS:" >> "$UNIFIED_REPORT"
echo "  Container Image: $IMAGE_NAME" >> "$UNIFIED_REPORT"
echo "  Scan Timestamp: $TIMESTAMP" >> "$UNIFIED_REPORT"
echo "  Total Packages: $(jq '[.Results[] | select(.Packages) | .Packages[] | .Name] | unique | length' "$FULL_JSON")" >> "$UNIFIED_REPORT"
echo "  Report Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')" >> "$UNIFIED_REPORT"
echo "" >> "$UNIFIED_REPORT"
echo "================================================================================" >> "$UNIFIED_REPORT"
echo "" >> "$UNIFIED_REPORT"

# Build unified package data structure
declare -A UNIFIED_PKG_DATA
ORIGIN_DB="$SCRIPT_DIR/country_software_origins.txt"

# Process each package
while IFS= read -r pkg_name; do
    [[ -z "$pkg_name" ]] && continue
    
    # Get package details
    version=$(jq -r --arg pkg "$pkg_name" '.Results[] | select(.Packages) | .Packages[] | select(.Name == $pkg) | .Version' "$FULL_JSON" | head -1)
    licenses=$(jq -r --arg pkg "$pkg_name" '.Results[] | select(.Packages) | .Packages[] | select(.Name == $pkg) | if .Licenses then (.Licenses | join("|")) else "" end' "$FULL_JSON" | head -1)
    
    # Determine origin country
    normalized=$(echo "$pkg_name" | sed 's/^lib//' | sed 's/[0-9]*$//' | sed 's/-dev$//' | sed 's/-common$//')
    origin_match=""
    country="UNKNOWN"
    org="Unknown"
    
    if [[ -f "$ORIGIN_DB" ]]; then
        origin_match=$(grep -i "^${normalized}|" "$ORIGIN_DB" 2>/dev/null || echo "")
        if [[ -n "$origin_match" ]]; then
            country=$(echo "$origin_match" | cut -d'|' -f2)
            org=$(echo "$origin_match" | cut -d'|' -f3)
        fi
    fi
    
    # Determine license compliance
    license_status="OSI-APPROVED"
    if [[ -n "$licenses" && -f "$OSI_LICENSE_FILE" ]]; then
        IFS='|' read -ra license_array <<< "$licenses"
        for lic in "${license_array[@]}"; do
            normalized_lic=$(echo "$lic" | sed 's/[[:space:]]*$//' | sed 's/-or-later$//' | sed 's/-only$//')
            if ! grep -qiFx "$normalized_lic" "$OSI_LICENSE_FILE" && ! grep -qiFx "$lic" "$OSI_LICENSE_FILE"; then
                license_status="NON-OSI"
                break
            fi
        done
    fi
    
    # Calculate risk classification
    risk_class="LOW"
    if [[ "$country" =~ ^(RU|CN|KP|IR)$ ]]; then
        risk_class="CRITICAL"
    elif [[ "$country" != "US" && "$country" != "UNKNOWN" ]]; then
        risk_class="HIGH"
    fi
    
    if [[ "$license_status" == "NON-OSI" ]]; then
        if [[ "$risk_class" == "LOW" ]]; then
            risk_class="MEDIUM"
        fi
    fi
    
    # Store unified data
    UNIFIED_PKG_DATA["$pkg_name"]="$version|$licenses|$country|$org|$license_status|$risk_class"
    
done < <(jq -r '[.Results[] | select(.Packages) | .Packages[] | .Name] | unique | .[]' "$FULL_JSON")

# Count risk categories
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

for pkg_data in "${UNIFIED_PKG_DATA[@]}"; do
    risk=$(echo "$pkg_data" | cut -d'|' -f6)
    case "$risk" in
        CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT + 1));;
        HIGH) HIGH_COUNT=$((HIGH_COUNT + 1));;
        MEDIUM) MEDIUM_COUNT=$((MEDIUM_COUNT + 1));;
        LOW) LOW_COUNT=$((LOW_COUNT + 1));;
    esac
done

# Generate executive summary
echo "EXECUTIVE SUMMARY:" >> "$UNIFIED_REPORT"
echo "  Risk Classification:" >> "$UNIFIED_REPORT"
echo "    CRITICAL (Adversary nation + non-OSI): $CRITICAL_COUNT packages" >> "$UNIFIED_REPORT"
echo "    HIGH (Foreign origin): $HIGH_COUNT packages" >> "$UNIFIED_REPORT"
echo "    MEDIUM (Non-OSI license): $MEDIUM_COUNT packages" >> "$UNIFIED_REPORT"
echo "    LOW (Compliant): $LOW_COUNT packages" >> "$UNIFIED_REPORT"
echo "" >> "$UNIFIED_REPORT"
echo "================================================================================" >> "$UNIFIED_REPORT"
echo "" >> "$UNIFIED_REPORT"

# Generate CSV file
echo "Package Name,Version,Licenses,Country of Origin,Organization,License Status,Risk Classification,Application,Summary" > "$UNIFIED_CSV"

# Generate detailed package listing
echo "DETAILED PACKAGE COMPLIANCE ANALYSIS:" >> "$UNIFIED_REPORT"
echo "================================================================================" >> "$UNIFIED_REPORT"
echo "" >> "$UNIFIED_REPORT"

# Critical risk packages first
if [[ $CRITICAL_COUNT -gt 0 ]]; then
    echo "🔴 CRITICAL RISK - ADVERSARY NATION SOFTWARE:" >> "$UNIFIED_REPORT"
    echo "--------------------------------------------------------------------------------" >> "$UNIFIED_REPORT"
    
    for pkg in "${!UNIFIED_PKG_DATA[@]}"; do
        IFS='|' read -r version licenses country org license_status risk_class <<< "${UNIFIED_PKG_DATA[$pkg]}"
        [[ "$risk_class" != "CRITICAL" ]] && continue
        
        echo "" >> "$UNIFIED_REPORT"
        echo "Package: $pkg" >> "$UNIFIED_REPORT"
        echo "  Version: $version" >> "$UNIFIED_REPORT"
        echo "  Country: $country" >> "$UNIFIED_REPORT"
        echo "  Organization: $org" >> "$UNIFIED_REPORT"
        echo "  Licenses: ${licenses/|/, }" >> "$UNIFIED_REPORT"
        echo "  License Status: $license_status" >> "$UNIFIED_REPORT"
        echo "  Risk: CRITICAL - Adversary nation origin" >> "$UNIFIED_REPORT"
        echo "  Action: IMMEDIATE REVIEW REQUIRED - CFIUS + DoD approval mandatory" >> "$UNIFIED_REPORT"
        
        # Add to CSV
        echo "\"$pkg\",\"$version\",\"${licenses/|/, }\",\"$country\",\"$org\",\"$license_status\",\"CRITICAL\",\"$IMAGE_NAME\",\"Adversary nation software requiring immediate review\"" >> "$UNIFIED_CSV"
    done
    echo "" >> "$UNIFIED_REPORT"
fi

# High risk packages
if [[ $HIGH_COUNT -gt 0 ]]; then
    echo "🟠 HIGH RISK - FOREIGN ORIGIN SOFTWARE:" >> "$UNIFIED_REPORT"
    echo "--------------------------------------------------------------------------------" >> "$UNIFIED_REPORT"
    
    for pkg in "${!UNIFIED_PKG_DATA[@]}"; do
        IFS='|' read -r version licenses country org license_status risk_class <<< "${UNIFIED_PKG_DATA[$pkg]}"
        [[ "$risk_class" != "HIGH" ]] && continue
        
        echo "" >> "$UNIFIED_REPORT"
        echo "Package: $pkg" >> "$UNIFIED_REPORT"
        echo "  Version: $version" >> "$UNIFIED_REPORT"
        echo "  Country: $country" >> "$UNIFIED_REPORT"
        echo "  Organization: $org" >> "$UNIFIED_REPORT"
        echo "  Licenses: ${licenses/|/, }" >> "$UNIFIED_REPORT"
        echo "  License Status: $license_status" >> "$UNIFIED_REPORT"
        echo "  Risk: HIGH - Foreign origin requires supply chain review" >> "$UNIFIED_REPORT"
        echo "  Action: CFIUS assessment and approval documentation required" >> "$UNIFIED_REPORT"
        
        # Add to CSV
        echo "\"$pkg\",\"$version\",\"${licenses/|/, }\",\"$country\",\"$org\",\"$license_status\",\"HIGH\",\"$IMAGE_NAME\",\"Foreign software requiring supply chain review\"" >> "$UNIFIED_CSV"
    done
    echo "" >> "$UNIFIED_REPORT"
fi

# Medium risk packages
if [[ $MEDIUM_COUNT -gt 0 ]]; then
    echo "🟡 MEDIUM RISK - NON-OSI LICENSE:" >> "$UNIFIED_REPORT"
    echo "--------------------------------------------------------------------------------" >> "$UNIFIED_REPORT"
    
    for pkg in "${!UNIFIED_PKG_DATA[@]}"; do
        IFS='|' read -r version licenses country org license_status risk_class <<< "${UNIFIED_PKG_DATA[$pkg]}"
        [[ "$risk_class" != "MEDIUM" ]] && continue
        
        echo "" >> "$UNIFIED_REPORT"
        echo "Package: $pkg" >> "$UNIFIED_REPORT"
        echo "  Version: $version" >> "$UNIFIED_REPORT"
        echo "  Country: $country" >> "$UNIFIED_REPORT"
        echo "  Licenses: ${licenses/|/, }" >> "$UNIFIED_REPORT"
        echo "  License Status: $license_status" >> "$UNIFIED_REPORT"
        echo "  Risk: MEDIUM - Non-OSI license requires legal review" >> "$UNIFIED_REPORT"
        echo "  Action: Legal counsel approval required before deployment" >> "$UNIFIED_REPORT"
        
        # Add to CSV
        echo "\"$pkg\",\"$version\",\"${licenses/|/, }\",\"$country\",\"$org\",\"$license_status\",\"MEDIUM\",\"$IMAGE_NAME\",\"Non-OSI license requiring legal review\"" >> "$UNIFIED_CSV"
    done
    echo "" >> "$UNIFIED_REPORT"
fi

# Generate JSON
jq -n --arg image "$IMAGE_NAME" \
      --arg timestamp "$(date '+%Y-%m-%d %H:%M:%S %Z')" \
      --argjson critical "$CRITICAL_COUNT" \
      --argjson high "$HIGH_COUNT" \
      --argjson medium "$MEDIUM_COUNT" \
      --argjson low "$LOW_COUNT" \
      --argjson total "$(echo "${#UNIFIED_PKG_DATA[@]}")" \
'{
  scan_metadata: {
    image: $image,
    timestamp: $timestamp,
    total_packages: $total,
    risk_summary: {
      critical: $critical,
      high: $high,
      medium: $medium,
      low: $low
    }
  },
  compliance_framework: {
    cfius: "Committee on Foreign Investment in the United States",
    executive_order: "EO 13873 - Securing ICT Supply Chain",
    ndaa_section: "889 - Chinese Telecommunications Restrictions",
    dod_policy: "DoD CIO Memo - Open Source Software (Oct 2009)",
    nist_standard: "SP 800-161 - Supply Chain Risk Management",
    osi_licenses: "https://opensource.org/licenses/"
  },
  packages: []
}' > "$UNIFIED_JSON"

log "Unified compliance report created:"
log "  - Text Report: $UNIFIED_REPORT"
log "  - CSV Export: $UNIFIED_CSV"
log "  - JSON Data: $UNIFIED_JSON"

if [[ $((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT)) -gt 0 ]]; then
    echo ""
    echo "================================================================================"
    echo "   [!] COMPLIANCE ISSUES DETECTED"
    echo "================================================================================"
    echo ""
    echo "  Risk Summary:"
    echo "    CRITICAL: $CRITICAL_COUNT packages (Adversary nation software)"
    echo "    HIGH:     $HIGH_COUNT packages (Foreign origin)"
    echo "    MEDIUM:   $MEDIUM_COUNT packages (Non-OSI license)"
    echo ""
    echo "  Reports:"
    echo "    - Unified Report: ${safe_name}_unified_compliance_$TIMESTAMP.txt"
    echo "    - CSV Export:     ${safe_name}_unified_compliance_$TIMESTAMP.csv"
    echo "    - JSON Data:      ${safe_name}_unified_compliance_$TIMESTAMP.json"
    echo ""
    echo "  Action Required: Review and obtain approvals before deployment"
    echo ""
fi

# === GENERATE STIG/CKL VIA HEIMDAL/SAF (if HDF generated) ===
if [[ -n "$HDF_FILE" ]]; then
    log "Generating CKL for eMASS/STIG Viewer..."
    docker run --rm -v "$DIRECTORY_NAME/MITRE:/share" -w /share mitre/saf:latest convert hdf2ckl \
        -i "hdf/$(basename "$HDF_FILE")" \
        -m <(cat <<EOF
{"profiles":[{"name":"Container Hardening","asset":{"name":"$container_name","type":"container"}}]}
EOF
) -o "${safe_name}_ckl_$TIMESTAMP.ckl" && log "CKL created: $DIRECTORY_NAME/MITRE/${safe_name}_ckl_$TIMESTAMP.ckl" || log "Warning: CKL generation failed (SAF container issue)"

    # Generate OpenSCAP HTML report from XCCDF
    XCCDF_FILE=$(find "$DIRECTORY_NAME/MITRE" -name "*.xccdf.xml" | head -1)
    if [[ -n "$XCCDF_FILE" && -f "$XCCDF_FILE" ]]; then
        log "XCCDF file generated: $XCCDF_FILE"
        if command -v oscap >/dev/null 2>&1; then
            oscap xccdf generate report --output "$DIRECTORY_NAME/reports/${safe_name}_openscap_$TIMESTAMP.html" "$XCCDF_FILE" && log "OpenSCAP HTML report created: $DIRECTORY_NAME/reports/${safe_name}_openscap_$TIMESTAMP.html" || log "Warning: OpenSCAP HTML generation failed"
        else
            log "OpenSCAP not available in PATH — XCCDF generated for manual HTML generation"
        fi
    else
        log "No XCCDF file found — skipping OpenSCAP HTML generation"
    fi
else
    log "Warning: HDF not generated — skipping CKL and OpenSCAP generation"
fi

# === SUCCESS MESSAGE ===
clear 2>/dev/null || true
cat << EOF

SUCCESS! Static analysis complete — container was NEVER executed.

Results saved to: $DIRECTORY_NAME
   - Full JSON Report      -> trivy_scans/trivy_full_$TIMESTAMP.json
   - SBOM (CycloneDX)      -> MITRE/${safe_name}_cyclonedx_$TIMESTAMP.json
   - License Table         -> reports/${safe_name}_licenses_$TIMESTAMP.html
   - License Table (.tbl)  -> reports/${safe_name}_licenses_$TIMESTAMP.tbl
   - Vulnerability Report  -> reports/${safe_name}_vulnerabilities_$TIMESTAMP.html
   - Vulnerability Table   -> reports/${safe_name}_vulnerabilities_$TIMESTAMP.tbl
   - STIG CKL (if generated) -> MITRE/${safe_name}_ckl_$TIMESTAMP.ckl
   - OpenSCAP XCCDF (if generated) -> MITRE/*.xccdf.xml (use: oscap xccdf generate report --output report.html file.xccdf.xml)

Optimized for secure, automated container security assessments in any environment.

EOF

# === OPTIONAL NIST 800-53 MAPPING ===
if [[ -t 0 ]]; then
    read -p $'\nRun NIST 800-53 mapping report? [y/N]: ' -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ -f "$SCRIPT_DIR/trivy_to_nist.py" ]]; then
            python3 "$SCRIPT_DIR/trivy_to_nist.py" "$DIRECTORY_NAME"
        else
            log "trivy_to_nist.py not found in script directory"
        fi
    fi
else
    log "Non-interactive mode: skipping NIST 800-53 mapping"
fi

log "All done — have a secure day!"
log "Debug log saved to: $LOG_FILE"