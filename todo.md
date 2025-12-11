1	Add --cache-dir to all Trivy calls	Fixes your fatal error; ensures offline DB reuse	trivy image --cache-dir "$CACHE_DIR" ... (create $CACHE_DIR=~/.trivy-cache first)
2	Use absolute paths everywhere	Prevents No such file in CI/air-gapped	SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRIVY_JSON="$SCRIPT_DIR/../$DIRECTORY_NAME/trivy_scans/..."
3	Validate Trivy version & DB freshness	Catches stale DB (your scan was 4h old)	```bash
4	Wrap saf in Docker with error capture	SAF crashes silently if image not loaded	```bash
docker run --rm -v "$PWD/$DIRECTORY_NAME/MITRE:/share" -w /share mitre/saf:latest convert hdf2ckl -i input.hdf -o output.ckl
5	Fix duplicate load_trivy_json in Python	Syntax error crashes script	Delete the second definition (lines ~48-51)
6	Add set -euo pipefail to bash	Script exits on any error	set -euo pipefail at top of container_hardening_check.sh
7	Use mktemp for temp files	Prevents collisions in parallel runs	UPDATED_HDF_FILE=$(mktemp)
8	Validate JSON before jq	Corrupt Trivy output = jq crash	bash<br>if ! jq empty "$TRIVY_JSON" 2>/dev/null; then echo "Invalid JSON"; exit 1; fi<br>
9	Add timeout to Trivy scans	Prevents hanging on large images	timeout 10m trivy image ...
10	Check Docker daemon before SAF	Air-gapped runners may not have Docker	bash<br>if ! docker info >/dev/null 2>&1; then echo "Docker not running"; exit 1; fi<br>
11	Auto-load SAF image if not present	Users forget docker load	Add utils/docker-load-saf.sh and call it
12	Use realpath for paths	Handles symlinks in GitLab	DIRECTORY_NAME=$(realpath "$DIRECTORY_NAME")
13	Add logging with timestamps	Audit trail for eMASS	log() { echo "[$(date +%H:%M:%S)] $*"; }
14	Validate image exists locally before scan	trivy image fails on missing image	`docker image inspect "$IMAGE_NAME" >/dev/null
15	Use jq filters instead of grep	More reliable parsing	`vuln_count=$(jq '[.Results[].Vulnerabilities[]?.Severity?
16	Add retry logic for Trivy DB update	Network blips in semi-gapped	for i in {1..3}; do trivy image --download-db-only && break; sleep 5; done
17	Sanitize filenames	: in image names breaks paths	`safe_name=$(echo "$IMAGE_NAME" | tr ':/' '__')`
18	Combine multiple Trivy scans into one JSON	Easier for trivy_to_nist.py to parse	`jq -s 'reduce .[] as $item ({}; .Results += $item.Results)' scan1.json scan2.json > combined.json`
19	Add help message	Improves usability	bash<br>if [[ "$1" == "--help" || "$1" == "-h" ]]; then echo "Usage: ..."; exit 0; fi<br>
20	Use consistent timestamp format	Easier correlation across files	TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
21	Add progress indicators	UX for long scans	echo "Scanning vulnerabilities..."; trivy ...
20	Use Python virtualenv	Prevent dependency conflicts	Add venv/ and requirements.txt with jq wrapper if needed
21	Add --quiet to Trivy in CI	Reduce log noise	trivy image --quiet ...
22	Export HDF with metadata	eMASS requires asset info	Add --asset-name "$container_name" --asset-type container to SAF
23	Add summary JSON	For dashboards	jq -n --arg score "$(calculate_score)" '{compliance: $score}' > summary.json
24	Add --skip-update for air-gapped	Prevent accidental online calls	trivy image --skip-update ...