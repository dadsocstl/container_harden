FROM ubuntu:22.04

LABEL maintainer="DoD Container Security Team" \
      description="STL Cyber - Container Hardening & Compliance Suite" \
      version="2025.1" \
      org.opencontainers.image.title="Container Security Scanner" \
      org.opencontainers.image.description="Comprehensive container security scanning with DoD compliance, CFIUS analysis, and NIST 800-53 mapping" \
      org.opencontainers.image.authors="3290178" \
      org.opencontainers.image.source="https://github.com/dod-cyber/container-hardening"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive \
    TRIVY_VERSION=0.57.1 \
    PYTHONUNBUFFERED=1 \
    DOCKER_HOST=unix:///var/run/docker.sock

# Install system dependencies
RUN apt-get update && apt-get install -y \
    bash \
    curl \
    wget \
    git \
    jq \
    python3 \
    python3-pip \
    docker.io \
    ca-certificates \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y trivy && \
    rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy all necessary files
COPY improved.sh /app/
COPY convert_tbl_to_html.py /app/
COPY trivy_to_nist.py /app/
COPY osi_approved_licenses.txt /app/
COPY country_software_origins.txt /app/
COPY container_hardening.hdf.json /app/
COPY generate_html_reports.sh /app/
COPY license-table.tpl /app/
COPY html.tpl /app/
COPY UNIFIED_COMPLIANCE_CSV_REFERENCE.md /app/

# Make scripts executable
RUN chmod +x /app/improved.sh /app/convert_tbl_to_html.py /app/trivy_to_nist.py /app/generate_html_reports.sh

# Create directories for outputs and cache
RUN mkdir -p /app/logs /app/results /app/trivy_db

# Copy entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command (shows usage)
CMD []

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD [ -f /app/improved.sh ] || exit 1

# Metadata
VOLUME ["/results"]
EXPOSE 0
