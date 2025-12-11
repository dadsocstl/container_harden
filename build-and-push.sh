#!/bin/bash
# build-and-push.sh - Build and push container scanner image

set -e

VERSION="${1:-latest}"
REGISTRY="${DOCKER_REGISTRY:-stlcyber}"
IMAGE_NAME="container-scanner"

echo "Building ${REGISTRY}/${IMAGE_NAME}:${VERSION}..."

# Build multi-architecture image
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag ${REGISTRY}/${IMAGE_NAME}:${VERSION} \
  --tag ${REGISTRY}/${IMAGE_NAME}:latest \
  --push \
  .

echo ""
echo "✅ Build complete!"
echo ""
echo "Image pushed to: ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
echo ""
echo "Test with:"
echo "  docker pull ${REGISTRY}/${IMAGE_NAME}:${VERSION}"
echo "  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v \$(pwd)/results:/results ${REGISTRY}/${IMAGE_NAME}:${VERSION} ubuntu:20.04"
